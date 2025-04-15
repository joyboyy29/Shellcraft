# Shellcraft

**Shellcraft** is a minimalistic, header-only Intel x64 shellcode generation library for C++.  
It provides a simple builder interface to craft custom call stubs, with support for:

- Windows x64 calling conventions (RCX, RDX, R8, R9 + stack)
- Up to 16 arguments (4 in registers and 12 on the stack)
- Register argument encoding
- Dynamic stack alignment (16-byte ABI compliance)
- Optional syscall stub generation
- Return value storage to memory
- Split shellcode output with a XOR encryption option
- Pure C++ with no dependencies

---

## Example:

```cpp
#include "shellcraft.hpp"
#include <vector>

void target_fn(int a, int b) {
    // do something
}

int main() {
    Shellcraft::Shellcraft builder;
    
    builder.set_function(reinterpret_cast<void*>(&target_fn))
           .add_arg(0xBAD)  // rcx
           .add_arg(0xC0DE) // rdx
           .store_result(reinterpret_cast<void*>(0xC0DEBABE)) // stores result at this address
           .dynamic_stack_align(true);
           
    std::vector<uint8_t> shellcode = builder.build();

    return 0;
}
```

## Shellcode output:
```asm
; Set RCX = 0xBAD
48 B9 AD 0B 00 00 00 00 00 00    mov rcx, 0xBAD

; Set RDX = 0xC0DE
48 BA DE C0 00 00 00 00 00 00    mov rdx, 0xC0DE

; Save RSP to R11
49 89 E3                         mov r11, rsp

; Align RSP to 0x10
48 83 E4 F0                      and rsp, 0xFFFFFFFFFFFFFFF0

; Allocate 0x28 bytes stack space
48 83 EC 28                      sub rsp, 0x28

; Set RAX = 0x64888562A429 (target_fn address)
48 B8 29 A4 62 85 88 64 00 00    mov rax, 0x64888562A429

; Call target fn
FF D0                            call rax

; Restore RSP from R11
4C 89 DC                         mov rsp, r11

; Store RAX into [0xC0DEBABE]
48 A3 BE BA DE C0 00 00 00 00    mov [0xC0DEBABE], rax

; Ret
C3                               ret
```
