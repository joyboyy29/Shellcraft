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
