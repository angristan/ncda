## [1.0.4](https://github.com/angristan/ncda/compare/v1.0.3...v1.0.4) (2026-08-22)


### Bug Fixes

* arm termination signals before probes ([c16b6d4](https://github.com/angristan/ncda/commit/c16b6d4f1581a6bbf854431c0a977937cf27631c))
* clean process state after final thread ([380a4b5](https://github.com/angristan/ncda/commit/380a4b5b3943ba34f2568808f317a4d1fdfb0c0c))
* explain eBPF startup failures ([1a8aff5](https://github.com/angristan/ncda/commit/1a8aff5c50945b170940b6bc1c6903900fc649c0))
* finish cleanup after runtime failures ([0344162](https://github.com/angristan/ncda/commit/0344162fb7c48b294d46bc5805281abf1d4f4eb5))
* ignore unsupported compatibility syscalls ([fdc3861](https://github.com/angristan/ncda/commit/fdc38614f3d10a1406a6b905a4b734b8ef45de51))
* invalidate attribution state after loss ([cd0b43b](https://github.com/angristan/ncda/commit/cd0b43b153c722c65a890b3f0e6a2ec6164f2a45))
* order BPF attachment and teardown ([a647287](https://github.com/angristan/ncda/commit/a647287f47182099cc2aa8fe901d30ff13100ae1))
* preserve exact pathname identity ([9d7c6e3](https://github.com/angristan/ncda/commit/9d7c6e3edd37f2f16ff69cb5ce90c5c03feaa3e1))
* preserve Linux descriptor lifecycle semantics ([444e56d](https://github.com/angristan/ncda/commit/444e56d993fe03f85adbdca3fb7aab5e823acf5d))
* reject compatibility syscall exits ([931c36e](https://github.com/angristan/ncda/commit/931c36e5c7a4b93c5abe21a9291e582d5e49cd50))
* report path resolution capability ([d6b44bb](https://github.com/angristan/ncda/commit/d6b44bbbfff891bcee5e676caa08e539e0b5a207))
* supervise capture runtime tasks ([dab78e6](https://github.com/angristan/ncda/commit/dab78e6e1f45d6d571c44d47079749b5215a7509))


### Performance Improvements

* dispatch syscall exits directly ([dbe2826](https://github.com/angristan/ncda/commit/dbe2826e3a8468b9a296b070ae0d1eac3f0467b8))

## [1.0.3](https://github.com/angristan/ncda/compare/v1.0.2...v1.0.3) (2026-08-21)


### Performance Improvements

* index process paths for cleanup ([f4a0597](https://github.com/angristan/ncda/commit/f4a0597c389d9aa297556e516c757d81d24bb222))

## [1.0.2](https://github.com/angristan/ncda/compare/v1.0.1...v1.0.2) (2026-08-21)


### Performance Improvements

* coalesce repeated IO events ([762c7a7](https://github.com/angristan/ncda/commit/762c7a7522ce4223abba09a45f8c2ee626cabca1))

## [1.0.1](https://github.com/angristan/ncda/compare/v1.0.0...v1.0.1) (2026-08-21)


### Bug Fixes

* close promptly after output stops ([3d10b3e](https://github.com/angristan/ncda/commit/3d10b3e1830ed76d3d352e73c8971169780c18c4))

# 1.0.0 (2026-08-21)


### Bug Fixes

* account for capture loss and drain on exit ([a1f3554](https://github.com/angristan/ncda/commit/a1f35543f87b0ce7d776bad11d347e74bd8c3046))
* correlate IO through portable raw hooks ([225d1e2](https://github.com/angristan/ncda/commit/225d1e28f1b21d09f101f2983a15c02c9895de8d))
* decouple container enrichment from ingestion ([66b3bde](https://github.com/angristan/ncda/commit/66b3bde99c09af3cf9125fecf502a1100633c86e))
* fail safely on ambiguous attribution ([b958539](https://github.com/angristan/ncda/commit/b9585390c68b0199129583a0450a67e13c451703))
* harden TUI interaction and rendering ([58b825a](https://github.com/angristan/ncda/commit/58b825aac93406c904ccc7ee49841ccb3ae457a9))
* invalidate descriptor lifecycle state ([8a5bebf](https://github.com/angristan/ncda/commit/8a5bebfba76f5de49b7975c93f0e99a1f902f068))
* isolate unresolved relative paths ([6fbc5df](https://github.com/angristan/ncda/commit/6fbc5df5e7fd09eadb8adb46157fc23374f44749))
* keep filtered activity views consistent ([e3d88fa](https://github.com/angristan/ncda/commit/e3d88fa149ebfee967bd7117d70e8b12f8ebc9a3))
* leave idle sparkline buckets blank ([f6f389d](https://github.com/angristan/ncda/commit/f6f389de324c0aa9ca7bdba8e83680fccffb9cf6))
* publish releases only from tags ([39d9882](https://github.com/angristan/ncda/commit/39d9882a5a6d23eec2c7ae030eb8f0bfc9ae58cb))
* restore CLI discovery and update TUI stack ([753fc0b](https://github.com/angristan/ncda/commit/753fc0b786620c79c222351aa1c0abd8b82872f3))
* saturate long-running activity counters ([705613f](https://github.com/angristan/ncda/commit/705613ffd28dcd974ccfedf59f9405278087f75d))
* separate pseudo descriptors from files ([b5f0f4a](https://github.com/angristan/ncda/commit/b5f0f4a2b24cc1c4348b33ebb643675a24a15ab9))
* stabilize sparkline time buckets ([7d91edf](https://github.com/angristan/ncda/commit/7d91edfad41b3a83166a98254c358f5bf6d718fb))
* synchronize high-resolution sparklines ([d84d3f1](https://github.com/angristan/ncda/commit/d84d3f1bfc2463732b5c42bc4ccc8eedc2354079)), closes [hi#resolution](https://github.com/hi/issues/resolution)
* use high-contrast selected rows ([a20fc71](https://github.com/angristan/ncda/commit/a20fc71e9ccda383fb60cb1f98e4f26cc8a47acf)), closes [hi#contrast](https://github.com/hi/issues/contrast)


### Features

* add responsive activity histories ([0dcc677](https://github.com/angristan/ncda/commit/0dcc67777f8618d3534dc16e2c32d51912bba4d8))
* capture broader file descriptor activity ([d515457](https://github.com/angristan/ncda/commit/d515457cc332c607c1f694d06e566346faf6f8d8))
* filter activity by path and process context ([fe94c2a](https://github.com/angristan/ncda/commit/fe94c2ad142cf247d7b067b5ee5241ca855f7576))
* initial implementation of ncda ([bc93410](https://github.com/angristan/ncda/commit/bc93410600517e57dd55515152f317ee2dd5795c))
* navigate and sort process activity ([e15ac6a](https://github.com/angristan/ncda/commit/e15ac6a0e6864dacef7dd65dfe2491c41ba5f7e9))
* resolve file paths via procfs and group I/O by container name ([6a0cfe5](https://github.com/angristan/ncda/commit/6a0cfe5c07eeb47a6c3d3d639cbf866649a8c8f5))
* use full terminal width ([1fca991](https://github.com/angristan/ncda/commit/1fca9917b506aded2f03f8512274490ff6bfab9d))
* validate portable syscall tracepoints ([38cd72e](https://github.com/angristan/ncda/commit/38cd72ec4f869994bd6d72536c77723d8420aa30))


### Performance Improvements

* bound ring buffer batches ([8265c9f](https://github.com/angristan/ncda/commit/8265c9fe271216adfae74de08fa036267d35e674))
* bound rolling aggregation costs ([7b890bc](https://github.com/angristan/ncda/commit/7b890bc1b902203f51582daca5993b34980fff4a))
* consume ring events asynchronously ([861ef6f](https://github.com/angristan/ncda/commit/861ef6fca533b73acc921454f77e31396be5fdb3))


### Reverts

* remove sparkline histories ([6405498](https://github.com/angristan/ncda/commit/6405498cc9343a7f6d5161da54bb009654b35833))

# Changelog

Release notes are generated from Conventional Commits by semantic-release.
