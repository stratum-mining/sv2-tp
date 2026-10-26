# Native Windows toolchain status

Native Visual Studio builds are not currently maintained in sv2-tp. The
Windows presets were removed, and native Windows builds are not covered by
our CI. Use the supported MinGW cross-compilation instructions in
[`build-windows.md`](./build-windows.md).

The remaining native Windows build-system code follows Bitcoin Core's
clang-cl toolchain. It no longer supports Microsoft's `cl.exe` compiler.
Upstream requires Visual Studio 2026 version 18.7 or later, with:

- The "Desktop development with C++" workload.
- The "MSBuild support for LLVM (clang-cl) toolset" component.
- The "C++ Clang Compiler for Windows" component.

See [dependencies.md](dependencies.md#compiler) for the compiler requirements.
Restoring native Windows support also requires maintained presets, IPC
dependencies, and build validation.
