# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

## [0.5.3] - 2022-02-10
### Added
- `Mmap::advise` and `MmapMut::advise`. [@nyurik](https://github.com/nyurik)

## [0.5.2] - 2022-01-10
### Added
- `flush`, `flush_async`, `flush_range` and `flush_async_range` to `MmapRaw` matching
  the corresponding methods on `MmapMut`.
  [@cberner](https://github.com/cberner)

## [0.5.1] - 2022-01-09
### Fixed
- Explicitly call `fstat64` on Linux, emscripten and l4re targets.
  [@adamreichold](https://github.com/adamreichold)

## [0.5.0] - 2021-09-19
### Added
- `MmapOptions` accepts any type that supports `RawHandle`/`RawFd` returning now.
  This allows using `memmap2` not only with Rust std types, but also with
  [async-std](https://github.com/async-rs/async-std) one.
  [@adamreichold](https://github.com/adamreichold)
- (unix) Memoize page size to avoid repeatedly calling into sysconf machinery.
  [@adamreichold](https://github.com/adamreichold)

### Changed
- (win) Use `std::os::windows::io::AsRawHandle` directly, without relying on `std::fs::File`.
  [@adamreichold](https://github.com/adamreichold)
- Do not panic when failing to release resources in Drop impls.
  [@adamreichold](https://github.com/adamreichold)

## [0.4.0] - 2021-09-16
### Added
- Optional [`StableDeref`](https://github.com/storyyeller/stable_deref_trait) support.
  [@SimonSapin](https://github.com/SimonSapin)

### Changed
- Mapping of zero-sized files is no longer an error.
  [@SimonSapin](https://github.com/SimonSapin)
- MSRV changed from 1.31 to 1.36

## [0.3.1] - 2021-08-15
### Fixed
- Integer overflow during file length calculation on 32bit targets.
- Stub implementation. [@Mrmaxmeier](https://github.com/Mrmaxmeier)

## [0.3.0] - 2021-06-10
### Changed
- `MmapOptions` allows mapping using Unix descriptors and not only `std::fs::File` now.
  [@mripard](https://github.com/mripard)

## [0.2.3] - 2021-05-24
### Added
- Allow compilation on unsupported platforms.
  The code will panic on access just like in `std`.
  [@jcaesar](https://github.com/jcaesar)

## [0.2.2] - 2021-04-03
### Added
- `MmapOptions::populate`. [@adamreichold](https://github.com/adamreichold)

### Fixed
- Fix alignment computation for `flush_async` to match `flush`.
  [@adamreichold](https://github.com/adamreichold)

## [0.2.1] - 2021-02-08
### Added
- `MmapOptions::map_raw` and `MmapRaw`. [@diwic](https://github.com/diwic)

## [0.2.0] - 2020-12-19
### Changed
- MSRV is 1.31 now (edition 2018).
- Make anonymous memory maps private by default on unix. [@CensoredUsername](https://github.com/CensoredUsername)
- Add `map_copy_read_only`. [@zseri](https://github.com/zseri)

## 0.1.0 - 2020-01-18
### Added
- Fork [memmap-rs](https://github.com/danburkert/memmap-rs).

### Changed
- Use `LICENSE-APACHE` instead of `README.md` for some tests since it's immutable.

### Removed
- `winapi` dependency. [memmap-rs/pull/89](https://github.com/danburkert/memmap-rs/pull/89)

[Unreleased]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.5.3...HEAD
[0.5.3]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/RazrFalcon/memmap2-rs/compare/v0.1.0...v0.2.0
