# PR Title

```
feat(gcp): Add Workload Identity Federation support with official google-cloud-auth library
```

# PR Description

```markdown
## Summary

Migrates GCP authentication from the unmaintained `durch/rust-goauth` and `durch/rust-jwt` libraries to the official `googleapis/google-cloud-rust` authentication library (`google-cloud-auth 1.6.0`).

This enables **Workload Identity Federation** support, allowing Vector to authenticate to GCP services using external account credentials—critical for Kubernetes/OpenShift deployments using federated identity.

## Changes

### Dependencies
- **Removed**: `goauth = "0.14.0"`, `smpl_jwt = "0.8.0"`
- **Added**: `google-cloud-auth = "1.6"`
- **Updated**: `toml = "0.9"` (required for compatibility)
- **Updated**: Rust toolchain to 1.91.1 (required by newer dependencies)

### Core Authentication (`src/gcp.rs`)
Complete rewrite using the official Google Cloud authentication library:
- Automatic Application Default Credentials (ADC) detection
- Support for service account credentials (existing functionality)
- **New**: Support for external account credentials (Workload Identity Federation)
- **New**: Support for API keys
- Automatic token refresh and caching
- Replaced `Scope` enum with `scopes` module containing scope constants

### Updated Components
All GCP sources and sinks updated to use new authentication API:
- `src/sources/gcp_pubsub.rs`
- `src/sinks/gcp/cloud_storage.rs`
- `src/sinks/gcp/pubsub.rs`
- `src/sinks/gcp/stackdriver/logs/config.rs`
- `src/sinks/gcp/stackdriver/metrics/config.rs`
- `src/sinks/gcp_chronicle/chronicle_unstructured.rs`

### Rust 1.91.1 Compatibility Fixes
Fixed lifetime elision lint errors in library crates:
- `lib/vector-config-macros/src/ast/container.rs`
- `lib/vector-config/src/schema/parser/component.rs`
- `lib/vector-config/src/schema/parser/query.rs`
- `lib/enrichment/src/vrl_util.rs`
- `lib/vector-core/src/event/array.rs`
- `lib/vector-core/src/event/util/log/all_fields.rs`
- `lib/vector-core/src/transform/mod.rs`
- `src/internal_events/parser.rs`
- `src/sinks/util/adaptive_concurrency/service.rs`
- `src/topology/controller.rs`

## Key Benefits

✅ **Workload Identity Federation**: Full support for external account credentials
✅ **Official Google Support**: Actively maintained by Google
✅ **Automatic Token Management**: Built-in token caching and refresh
✅ **Backward Compatible**: No configuration changes required for existing users

## Backward Compatibility

**No breaking changes**—all existing authentication methods continue to work:
- `credentials_path` configuration option ✓
- `GOOGLE_APPLICATION_CREDENTIALS` environment variable ✓
- `api_key` configuration option ✓
- **New**: Automatic detection and support for external account credentials

## Example: Workload Identity Federation

Users can now provide external account credentials for federated authentication:

```toml
[sinks.my_gcp_sink]
type = "gcp_cloud_storage"
bucket = "my-bucket"
credentials_path = "/path/to/external-account-creds.json"
```

Where `external-account-creds.json` contains:
```json
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/.../workloadIdentityPools/.../providers/...",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "file": "/var/run/secrets/tokens/gcp-ksa/token"
  },
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/.../:generateAccessToken"
}
```

## Testing

```bash
# All GCP tests passing
cargo test --lib --no-default-features --features sinks-gcp,sources-gcp_pubsub gcp::tests
```

Results:
```
running 4 tests
test gcp::tests::skip_authentication ... ok
test gcp::tests::fails_bad_api_key ... ok
test gcp::tests::uses_api_key ... ok
test sinks::gcp::tests::serialize_gcp_series ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured
```

## Documentation

- `MIGRATION_SUMMARY.md`: Complete technical migration details
- `OPENSHIFT_GCP_TESTING.md`: Guide for testing with OpenShift/Kubernetes on GCP

## Related Issues

Closes #[issue-number-for-workload-identity-support] (if applicable)

---

**Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>**
```
