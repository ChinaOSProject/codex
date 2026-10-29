# Vendored seccompiler 0.5.0

Upstream: https://github.com/rust-vmm/seccompiler

This is the complete source from upstream `v0.5.0`
(`c3cf77d65815037931ae5bc2fca010713defdc8c`) with the following reviewed
ChinaOSProject dependency commits applied:

- `9e0a1f66e49c148ceb42b5d4b302d3ec84937236`: LoongArch64 target,
  Linux 6.12 syscall table, and architecture/filter safety tests.
- `8bb8d11bbd729d6b1a64f2aa1ca466cc802f043b`: check TSYNC syscall
  failures without assuming that a successful syscall clears errno.

The imported source is unchanged. `README.codex.md` records its provenance.
The upstream Apache-2.0 and BSD-3-Clause licenses are retained in full.

Verified source archive SHA-256:
`55e884b8042af8ec1dbd54c24812438b150335862690cf317fdc6bd0fc3f0876`.
Original crates.io 0.5.0 crate SHA-256:
`a4ae55de56877481d112a559bbc12667635fdaf5e005712fd4e2b2fa50ffc884`.

The dependency report and complete patch are archived at:
https://github.com/ChinaOSProject/DEPENDENCY_CHANGES/blob/0dda7cf54c798e5ce2ae4a9fb6b99506aaf76ebb/lib_seccompiler_v0.5.0_loongarch64.md

This copy provides the correct LoongArch64 audit architecture while preserving
architecture checks and the existing seccomp filter policy on all targets.
