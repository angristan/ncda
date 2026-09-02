# Changelog

# [1.1.0](https://github.com/angristan/ncda/compare/v1.0.4...v1.1.0) (2026-09-02)


### Features

* add first-class Nix package ([#1](https://github.com/angristan/ncda/issues/1)) ([c4c7422](https://github.com/angristan/ncda/commit/c4c742276f7df3c0b25253c5404f1d50b45bdd2e))

## [1.0.4](https://github.com/angristan/ncda/compare/v1.0.3...v1.0.4) — 2026-08-22

- Corrected descriptor lifecycle handling, compatibility syscall filtering, and final-thread process cleanup.
- Preserved exact Linux pathname identity and invalidated cached attribution after capture loss.
- Ordered probe attachment and shutdown so capture starts and stops safely.
- Supervised critical runtime tasks and reduced syscall-exit map lookups.

## [1.0.3](https://github.com/angristan/ncda/compare/v1.0.2...v1.0.3) — 2026-08-21

- Made process cleanup proportional to the paths touched by that process instead of the full historical tree.

## [1.0.2](https://github.com/angristan/ncda/compare/v1.0.1...v1.0.2) — 2026-08-21

- Coalesced repeated I/O events without changing byte, operation, latency, or lifecycle accounting.

## [1.0.1](https://github.com/angristan/ncda/compare/v1.0.0...v1.0.1) — 2026-08-21

- Kept kernel ring draining lossless while avoiding unnecessary aggregation after output closes.

## [1.0.0](https://github.com/angristan/ncda/releases/tag/v1.0.0) — 2026-08-21

Initial release:

- Live system-wide file I/O capture with eBPF.
- Tree, flat, process, filter, and stdout views.
- Userspace path and container attribution with fail-safe unresolved paths.
- Visible kernel and userspace loss accounting.
- Reproducible benchmark and native Linux x86_64/ARM64 releases.
