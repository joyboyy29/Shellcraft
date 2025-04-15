#pragma once

#include <vector>
#include <cstdint>
#include <optional>
#include <cstring>
#include <algorithm>
#include <random>
#include <cassert>

namespace Shellcraft {

    enum class StubMode {
        Standalone,
        MemoryBacked,
        Syscall
    };

    struct ShellcodeCfg {
        void* function_ptr = nullptr;
        std::vector<uint64_t> arguments;
        void* store_result = nullptr;
        StubMode mode = StubMode::Standalone;
        std::optional<uint32_t> syscall_id;
        // jmp instead of ret
        bool exit_via_jmp = false;
        void* exit_target = nullptr;
        bool dynamic_stack_align = false;
    };

    inline std::vector<uint8_t> generate_shellcode_data_blob(const ShellcodeCfg& cfg) {
        constexpr size_t max_args = 16;
        std::vector<uint8_t> blob;
        blob.reserve(max_args * 8 + 16);
    
        size_t arg_count = std::min(cfg.arguments.size(), max_args);
        for (size_t i = 0; i < arg_count; ++i) {
            uint64_t val = cfg.arguments[i];
            const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&val);
            blob.insert(blob.end(), ptr, ptr + 8);
        }
        for (size_t i = arg_count; i < max_args; ++i)
            blob.insert(blob.end(), 8, 0x00);
    
        const uint8_t* fbytes = reinterpret_cast<const uint8_t*>(&cfg.function_ptr);
        blob.insert(blob.end(), fbytes, fbytes + 8);
    
        const uint8_t* rbytes = reinterpret_cast<const uint8_t*>(&cfg.store_result);
        blob.insert(blob.end(), rbytes, rbytes + 8);
    
        return blob;
    }
    
    inline std::vector<std::pair<std::vector<uint8_t>, uint8_t>>
    split_shellcode_chunks(const std::vector<uint8_t>& shellcode, size_t chunk_size, bool encrypt = true) {
        std::vector<std::pair<std::vector<uint8_t>, uint8_t>> chunks;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(1, 255);

        for (size_t i = 0; i < shellcode.size(); i += chunk_size) {
            size_t size = std::min(chunk_size, shellcode.size() - i);
            std::vector<uint8_t> chunk;
            chunk.reserve(size);
            chunk.insert(chunk.end(), shellcode.begin() + i, shellcode.begin() + i + size);
            uint8_t key = 0;

            if (encrypt) {
                key = static_cast<uint8_t>(dist(gen));
                for (auto& b : chunk)
                    b ^= key;
            }
            chunks.emplace_back(chunk, key);
        }
        return chunks;
    }

    inline size_t estimate_shellcode_size(const ShellcodeCfg& cfg) {
        size_t size = 0;
        
        // for x64 calling convention rcx, rdx, r8, r9 store the first 4 args
        // rcx, rdx, r8, r9
        for (size_t i = 0; i < std::min(cfg.arguments.size(), size_t(4)); ++i) {
            if (cfg.arguments[i] == 0) {
                size += 3; // xor reg, reg  → e.g., 0x48 31 C9
            } else {
                size += 2 + 8; // mov reg, imm64  → 0x48 B9 + 8 bytes
            }
        }
        
        // the remaining arguments are passed onto the stack from right to left
        // stack args
        for (size_t i = cfg.arguments.size(); i-- > 4;) {
            uint64_t val = cfg.arguments[i];
            if (val <= 0xFFFFFFFF) {
                size += 1 + 4; // push imm32
            } else {
                size += 2 + 8 + 1; // mov rax, imm64 + push rax
            }
        }
    
        if (cfg.dynamic_stack_align) {
            size += 3; // mov r11, rsp
            size += 4; // and rsp, -0x10 // aligning stack to 16 bytes
            size += 4; // sub rsp, 0x28
        } else {
            size += 4; // sub rsp, 0x28
        }
    
        // mov rax, function_ptr
        size += 2 + 8;
    
        // call rax
        size += 2;
    
        // Restore stack
        if (cfg.dynamic_stack_align) {
            size += 3; // mov rsp, r11
        } else {
            size += 4; // add rsp, ...
        }
    
        // Store result
        if (cfg.store_result) {
            size += 2 + 8; // mov [imm64], rax
        }
    
        // Exit
        if (cfg.exit_via_jmp && cfg.exit_target) {
            size += 2 + 8; // mov rax, addr
            size += 2;     // jmp rax
        } else {
            size += 1; // ret
        }
    
        return size;
    }

    inline std::vector<uint8_t> generate_shellcode(const ShellcodeCfg& cfg) {
        // assertions
        if (cfg.mode == StubMode::Syscall)
            assert(cfg.syscall_id.has_value() && "syscall mode requires a syscall id");
        if (cfg.exit_via_jmp)
            assert(cfg.exit_target != nullptr && "exit_target must be set when exit_via_jmp is true");
        if (cfg.mode == StubMode::MemoryBacked)
            assert(false && "not implemented yet lol");
        if (cfg.mode == StubMode::Standalone)
            assert(cfg.function_ptr != nullptr && "set fn ptr in standalone mode");
    
        std::vector<uint8_t> code;
        code.reserve(estimate_shellcode_size(cfg) + 32);
        std::vector<std::pair<size_t, size_t>> rip_patches;
    
        auto emit = [&](auto... bytes) {
            uint8_t arr[] = { static_cast<uint8_t>(bytes)... };
            code.insert(code.end(), arr, arr + sizeof...(bytes));
        };
    
        auto emit_xor_reg = [&](uint8_t rex, uint8_t modrm) {
            emit(rex, 0x31, modrm); // xor reg, reg
        };
    
        size_t arg_count = cfg.arguments.size();
        size_t stack_arg_count = (arg_count > 4) ? (arg_count - 4) : 0;
    
        if (cfg.mode == StubMode::Syscall) {
            emit(0x4C, 0x8B, 0xD1);             // mov r10, rcx
            emit(0xB8);                         // mov eax, syscall_id
            uint32_t id = cfg.syscall_id.value();
            code.insert(code.end(), reinterpret_cast<uint8_t*>(&id), reinterpret_cast<uint8_t*>(&id) + 4);
            emit(0x0F, 0x05);                   // syscall
            emit(0xC3);                         // ret
            return code;
        }
    
        if (cfg.mode == StubMode::Standalone) {
            if (arg_count > 0) {
                if (cfg.arguments[0] == 0)
                    emit_xor_reg(0x48, 0xC9);                  // xor rcx, rcx
                else {
                    emit(0x48, 0xB9);                          // mov rcx, imm64
                    code.insert(code.end(), reinterpret_cast<const uint8_t*>(&cfg.arguments[0]),
                                reinterpret_cast<const uint8_t*>(&cfg.arguments[0]) + 8);
                }
            }
            if (arg_count > 1) {
                if (cfg.arguments[1] == 0)
                    emit_xor_reg(0x48, 0xD2);                  // xor rdx, rdx
                else {
                    emit(0x48, 0xBA);                          // mov rdx, imm64
                    code.insert(code.end(), reinterpret_cast<const uint8_t*>(&cfg.arguments[1]),
                                reinterpret_cast<const uint8_t*>(&cfg.arguments[1]) + 8);
                }
            }
            if (arg_count > 2) {
                if (cfg.arguments[2] == 0)
                    emit_xor_reg(0x4D, 0xC0);                  // xor r8, r8
                else {
                    emit(0x49, 0xB8);                          // mov r8, imm64
                    code.insert(code.end(), reinterpret_cast<const uint8_t*>(&cfg.arguments[2]),
                                reinterpret_cast<const uint8_t*>(&cfg.arguments[2]) + 8);
                }
            }
            if (arg_count > 3) {
                if (cfg.arguments[3] == 0)
                    emit_xor_reg(0x4D, 0xC9);                  // xor r9, r9
                else {
                    emit(0x49, 0xB9);                          // mov r9, imm64
                    code.insert(code.end(), reinterpret_cast<const uint8_t*>(&cfg.arguments[3]),
                                reinterpret_cast<const uint8_t*>(&cfg.arguments[3]) + 8);
                }
            }
    
            for (size_t i = arg_count; i-- > 4;) {
                uint64_t val = cfg.arguments[i];
                if (val <= 0xFFFFFFFF) {
                    emit(0x68); // push imm32
                    uint32_t v32 = static_cast<uint32_t>(val);
                    code.insert(code.end(), reinterpret_cast<uint8_t*>(&v32),
                                reinterpret_cast<uint8_t*>(&v32) + 4);
                } else {
                    emit(0x48, 0xB8); // mov rax, imm64
                    code.insert(code.end(), reinterpret_cast<uint8_t*>(&val),
                                reinterpret_cast<uint8_t*>(&val) + 8);
                    emit(0x50);       // push rax
                }
            }
    
            if (cfg.dynamic_stack_align) {
                emit(0x49, 0x89, 0xE3);       // mov r11, rsp (save rsp)
                emit(0x48, 0x83, 0xE4, 0xF0); // and rsp, -0x10 (align rsp to 16 bytes)
                emit(0x48, 0x83, 0xEC, 0x28); // sub rsp, 0x28 (shadow space)
            } else {
                emit(0x48, 0x83, 0xEC, 0x28); // sub rsp, 0x28 (shadow space)
            }
    
            emit(0x48, 0xB8); // mov rax, function_ptr
            code.insert(code.end(), reinterpret_cast<const uint8_t*>(&cfg.function_ptr),
                        reinterpret_cast<const uint8_t*>(&cfg.function_ptr) + 8);
    
            emit(0xFF, 0xD0); // call rax
    
            uint8_t rsp_restore = 0x28 + static_cast<uint8_t>(stack_arg_count * 8);
    
            if (cfg.dynamic_stack_align) {
                emit(0x4C, 0x89, 0xDC); // mov rsp, r11 (restore rsp)
            } else {
                emit(0x48, 0x83, 0xC4, rsp_restore); // add rsp, 0x28 (+ stack args)
            }
    
            if (cfg.store_result) {
                emit(0x48, 0xA3); // mov [imm64], rax
                code.insert(code.end(), reinterpret_cast<const uint8_t*>(&cfg.store_result),
                            reinterpret_cast<const uint8_t*>(&cfg.store_result) + 8);
            }
    
            if (cfg.exit_via_jmp && cfg.exit_target) {
                emit(0x48, 0xB8); // mov rax, exit_target
                code.insert(code.end(), reinterpret_cast<const uint8_t*>(&cfg.exit_target),
                            reinterpret_cast<const uint8_t*>(&cfg.exit_target) + 8);
                emit(0xFF, 0xE0); // jmp rax
            } else {
                emit(0xC3); // ret
            }
    
            return code;
        }
    
        return {};
    }

    struct Shellcraft {
        ShellcodeCfg cfg;

        Shellcraft& set_function(void* fn) { cfg.function_ptr = fn; return *this; }
        Shellcraft& add_arg(uint64_t val) { cfg.arguments.push_back(val); return *this; }
        Shellcraft& store_result(void* dst) { cfg.store_result = dst; return *this; }
        Shellcraft& mode(StubMode m) { cfg.mode = m; return *this; }
        Shellcraft& syscall_id(uint32_t id) { cfg.syscall_id = id; return *this; }
        Shellcraft& exit_jmp_to(void* jmp_target) {
            cfg.exit_via_jmp = true; cfg.exit_target = jmp_target; return *this;
        }
        Shellcraft& dynamic_stack_align(bool enable = true) { cfg.dynamic_stack_align = enable; return *this; }

        std::vector<uint8_t> build() { return generate_shellcode(cfg); }
        ShellcodeCfg& config() { return cfg; }
    };

}
