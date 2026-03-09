# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vector is a high-performance, end-to-end observability data pipeline written in Rust. It collects, transforms, and routes logs, metrics, and traces. The project emphasizes reliability, performance, and vendor-neutrality.

## Build Commands

### Development Builds
```bash
# Quick development build
cargo build --no-default-features --features ocp-logging

# Build with specific component
cargo build --no-default-features --features sinks-console

# Release build
make build
# Or for offline build
make build-offline
```

### Testing
```bash
# Run unit tests (requires cargo-nextest installed)
cargo vdev test
# Or via make
make test

# Run tests for specific component
cargo test --lib --no-default-features --features sinks-console sinks::console

# Run integration test for specific service
cargo vdev int test aws
# List available integration tests
cargo vdev int show

# Run behavioral tests
make test-behavior

# Run E2E Kubernetes tests
make test-e2e-kubernetes
```

### Code Quality Checks
```bash
# Format code (always run before committing)
cargo vdev check fmt
# Or: cargo fmt

# Run Clippy linter
cargo vdev check rust --clippy

# Check component features are set up correctly
cargo vdev check component-features

# Check component docs are up to date
cargo vdev check component-docs

# Update license file
cargo vdev build licenses

# All checks (slow)
make check-all
```

### Running Vector
```bash
# Run Vector with a config file
cargo run -- --config my_config.toml

# Run with specific features
cargo run --no-default-features --features ocp-logging -- --config my_config.toml
```

## Architecture Overview

### Component Types

Vector has three primary component types that form a processing pipeline:

1. **Sources** (`src/sources/`) - Ingest data from external systems (files, kafka, http, journald, kubernetes_logs, etc.)
2. **Transforms** (`src/transforms/`) - Process and modify events (remap, filter, reduce, log_to_metric, etc.)
3. **Sinks** (`src/sinks/`) - Send data to destinations (aws_cloudwatch_logs, elasticsearch, loki, prometheus, etc.)

### Key Directories

- `src/` - Main Vector source code
  - `src/sources/`, `src/transforms/`, `src/sinks/` - Component implementations
  - `src/config/` - Configuration loading and validation
  - `src/topology/` - Pipeline topology construction and management
  - `src/internal_events/` - Instrumentation and telemetry events
  - `src/codecs/` - Encoding/decoding for different data formats
  - `src/kubernetes/` - Kubernetes-specific client and machinery
- `lib/` - Standalone libraries not dependent on Vector core
  - `lib/vector-*` - Core Vector libraries (vector-core, vector-config, vector-buffers, etc.)
  - `lib/vrl/` - VRL (Vector Remap Language) lives in a separate repository but is used as a workspace dependency
- `vdev/` - Development CLI tool (`cargo vdev`)
- `tests/` - High-level integration and E2E tests
- `benches/` - Performance benchmarks

### Data Flow

Events flow through Vector's topology as follows:
1. Sources produce events from external systems
2. Events enter the topology via `BufferSender`
3. Transforms process events in the pipeline
4. Sinks receive events and send to destinations
5. The topology manages concurrency, buffering, and backpressure

### Configuration System

Vector uses a strongly-typed configuration system:
- Config files are YAML, TOML, or JSON
- Schemas are auto-generated from Rust types using `vector-config` macros
- Component configs must implement `SourceConfig`, `TransformConfig`, or `SinkConfig`
- The config is loaded and validated before building the topology

### VRL (Vector Remap Language)

VRL is Vector's domain-specific language for transforming observability data. It's used primarily in the `remap` transform. The VRL codebase exists in a separate repository but is vendored/referenced as a workspace dependency.

## Development Workflow

### Adding a New Component

When adding a new source, sink, or transform:

1. **Feature Flag**: Add it behind a feature flag in `Cargo.toml` with name matching the component (e.g., `sinks-my_sink`)
2. **Implementation**: Create module in appropriate directory (`src/sources/`, `src/sinks/`, or `src/transforms/`)
3. **Config Struct**: Implement the config trait (`SourceConfig`, `SinkConfig`, `TransformConfig`)
4. **Tests**: Add unit tests and integration tests if it connects to external services
5. **Instrumentation**: Add internal events in `src/internal_events/` for observability
6. **Documentation**: Component docs are auto-generated from code annotations

### Feature Flags

Components are compiled conditionally using Cargo features:
- Each component has a corresponding feature flag (e.g., `sources-kafka`, `sinks-elasticsearch`)
- Feature sets like `ocp-logging` bundle specific components for particular use cases
- Build only needed components to speed up compilation during development

### Testing Philosophy

- Unit tests should not require external services
- Integration tests require Docker and test against real services
- Integration tests are managed via `cargo vdev int` which handles service lifecycle
- Behavioral tests validate Vector's config and transformation behavior
- E2E tests validate full deployment scenarios (especially for Kubernetes)

### Sink Health Checks

When implementing health checks for sinks:
- Prefer false positives over false negatives (better to pass when might fail than fail when would succeed)
- Mimic what the sink itself does rather than performing extra operations
- Avoid operations requiring permissions the sink doesn't need (e.g., listing all S3 buckets)
- Document side effects and handle dynamic data dependencies gracefully

### Code Style

- Run `cargo fmt` before committing
- Use Tracing crate's key/value style for logging: `warn!(message = "Failed to merge value.", %error);`
- Capitalize log messages and end with a period
- Use `%error` (Display) not `?error` (Debug) for error formatting
- Avoid panics except for clear bugs where Vector cannot safely proceed - must document in function docs

## Docker/Podman Environment

For consistent builds, especially for cross-compilation:

```bash
# Enter development environment
make environment

# Run commands in environment
make test ENVIRONMENT=true
make build ENVIRONMENT=true
make check ENVIRONMENT=true
```

The environment uses volumes for caching to speed up rebuilds.

## Integration Test Development

Integration tests require Docker services:
1. Service must run in a Docker container on a unique port
2. Add `test-integration-<name>` target to Makefile
3. Configure service startup before running tests
4. Tests use `AUTOSPAWN=true` (default) to automatically manage service lifecycle

## Important Context

- This is a fork/variant maintained for Red Hat OpenShift (note the `ocp-logging` feature set)
- The main branch for this change is based on `v0.47.0-rh`, not `master`
- Current working branch is `v0.47.0-rh-google-cloud-auth`
- Minimum Rust version is specified in `Cargo.toml` as `rust-version`
- Rust version is controlled by `rust-toolchain.toml` (currently 1.94) and needed to be updated to avoid conflicts with other packages
- The project uses `cargo-nextest` instead of standard `cargo test` for better test execution
