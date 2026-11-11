# Native Windows toolchain status

Windows is not currently supported by sv2-tp. The Windows build-system
changes are retained as preparation for [PR #93](https://github.com/stratum-mining/sv2-tp/pull/93).
The Windows presets were removed, and native Windows builds are not covered
by our CI. The inherited MinGW instructions in
[`build-windows.md`](./build-windows.md) remain available as reference.

The remaining native Windows build-system code follows Bitcoin Core's
clang-cl toolchain. It no longer supports Microsoft's `cl.exe` compiler.
Upstream requires Visual Studio 2026 version 18.7 or later, with:

- The "Desktop development with C++" workload.
- The "MSBuild support for LLVM (clang-cl) toolset" component.
- The "C++ Clang Compiler for Windows" component.

See [dependencies.md](dependencies.md#compiler) for the compiler requirements.
Completing native Windows support also requires maintained presets, IPC
dependencies, and build validation.
