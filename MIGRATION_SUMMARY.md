# GCP Authentication Library Migration Summary

## Overview

Successfully migrated from `durch/rust-goauth` and `durch/rust-jwt` to the official `googleapis/google-cloud-rust` authentication library (`google-cloud-auth 1.6.0`).

## Key Benefits

✅ **Workload Identity Federation Support**: Full support for external account credentials

✅ **Official Google Support**: Actively maintained by Google

✅ **Automatic Token Management**: Built-in token caching and refresh

✅ **Backward Compatible**: No configuration changes required for end users

## Changes Made

### 1. Dependencies (Cargo.toml)
- **Removed**: `goauth = "0.14.0"`, `smpl_jwt = "0.8.0"`
- **Added**: `google-cloud-auth = "1.6"`
- **Updated**: `toml = "0.9"` (required for compatibility)

### 2. Rust Toolchain
- **Updated**: `rust-toolchain.toml` from 1.83 to **1.88.0**
- Required by `google-cloud-auth` 1.6 and newer dependencies

### 3. Core Authentication (src/gcp.rs)
Complete rewrite using google-cloud-auth 1.6 API:
- Uses `Builder::default()` with `.with_scopes()` for configuration
- Leverages `AccessTokenCredentials` for direct token access
- Automatic ADC (Application Default Credentials) detection
- Support for:
  - Service account credentials
  - External account credentials (workload identity)
  - API keys
  - Metadata server (GCE/GKE)

### 4. Updated All GCP Components
Migrated from `Scope` enum to `scopes` module strings:
- `src/sources/gcp_pubsub.rs`
- `src/sinks/gcp/cloud_storage.rs`
- `src/sinks/gcp/pubsub.rs`
- `src/sinks/gcp/stackdriver/logs/config.rs`
- `src/sinks/gcp/stackdriver/metrics/config.rs`
- `src/sinks/gcp_chronicle/chronicle_unstructured.rs`

### 5. Lifetime Fixes
Fixed lifetime elision lint errors in several library crates to compile with Rust 1.88:
- `lib/vector-config-macros/src/ast/container.rs`
- `lib/vector-config/src/schema/parser/component.rs`
- `lib/vector-config/src/schema/parser/query.rs`
- `lib/enrichment/src/vrl_util.rs`

## API Changes

### Old API (durch/goauth)
```rust
use crate::gcp::{Scope, GcpAuthConfig};

let auth = config.auth.build(Scope::PubSub).await?;
```

### New API (google-cloud-auth)
```rust
use crate::gcp::{scopes, GcpAuthConfig};

let auth = config.auth.build(&[scopes::PUBSUB]).await?;
```

## Available Scopes

Defined in `src/gcp.rs::scopes`:
- `CLOUD_STORAGE`: Cloud Storage read/write
- `PUBSUB`: Cloud Pub/Sub
- `MONITORING_WRITE`: Cloud Monitoring (Stackdriver)
- `LOGGING_WRITE`: Cloud Logging
- `CLOUD_PLATFORM`: Full cloud platform access

## Workload Identity Federation Support

The new implementation automatically supports external account credentials. Simply provide an external account credentials JSON file:

```json
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "file": "/var/run/secrets/tokens/gcp-ksa/token"
  },
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/SA_EMAIL@PROJECT_ID.iam.gserviceaccount.com:generateAccessToken"
}
```

Via configuration:
```toml
[sinks.my_gcp_sink]
type = "gcp_cloud_storage"
bucket = "my-bucket"
credentials_path = "/path/to/external-account-creds.json"
```

Or via environment variable:
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/external-account-creds.json
```

## Testing

Build and test with GCP features:
```bash
# Build with GCP support
cargo build --no-default-features --features gcp

# Run GCP module tests
cargo test --lib gcp

# Run integration tests
cargo vdev int test gcp-pubsub
cargo vdev int test gcp-cloud-storage
```

## Configuration Compatibility

**No breaking changes** for end users:
- `api_key` configuration option works as before
- `credentials_path` configuration option works as before
- `GOOGLE_APPLICATION_CREDENTIALS` environment variable works as before
- **New**: Automatic support for external account credentials

## Files Modified

**Core changes:**
- `Cargo.toml` - Dependencies
- `rust-toolchain.toml` - Rust version
- `src/gcp.rs` - Complete rewrite

**Component updates:**
- 6 source/sink files (scope API updates)

**Library fixes:**
- 4 library files (lifetime annotations)

**Total lines changed:** ~6,500 insertions, ~3,000 deletions

## Verification

Successfully compiled with:
```
cargo check --no-default-features --features gcp
```

Status: ✅ **READY FOR TESTING**
