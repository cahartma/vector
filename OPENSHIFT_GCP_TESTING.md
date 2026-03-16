# Testing Vector GCP Authentication with OpenShift on GCP

This guide provides step-by-step instructions for testing Vector's new Google Cloud authentication implementation using Workload Identity Federation with an OpenShift cluster running on GCP.

## Overview

Vector now supports **Workload Identity Federation** using external account credentials, allowing OpenShift workloads to authenticate to GCP services without storing service account keys as secrets.

## Prerequisites

- OpenShift cluster running on GCP (ROSA, OSD, or self-managed)
- GCP project with appropriate permissions
- `gcloud` CLI installed and configured
- `oc` CLI installed and logged into OpenShift cluster
- Appropriate IAM permissions in GCP to create service accounts and workload identity pools

## Architecture

```
OpenShift Pod (Vector)
  └─ ServiceAccount with projected token
      └─ Workload Identity Federation
          └─ GCP Workload Identity Pool
              └─ Service Account Impersonation
                  └─ GCP Services (Cloud Storage, Pub/Sub, etc.)
```

## Part 1: GCP Workload Identity Federation Setup

### Step 1: Set Environment Variables

```bash
# Your GCP project
export PROJECT_ID="your-gcp-project-id"
export PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')

# Workload Identity configuration
export POOL_ID="openshift-vector-pool"
export PROVIDER_ID="openshift-provider"
export SERVICE_ACCOUNT_NAME="vector-sa"
export SERVICE_ACCOUNT_EMAIL="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# OpenShift configuration
export OPENSHIFT_NAMESPACE="vector-test"
export OPENSHIFT_SA_NAME="vector"
```

### Step 2: Create GCP Service Account

Create a service account that Vector will impersonate:

```bash
# Create the service account
gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME \
    --project=$PROJECT_ID \
    --display-name="Vector Service Account" \
    --description="Service account for Vector running on OpenShift"

# Grant appropriate permissions (adjust based on your needs)
# Example: Cloud Storage permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/storage.objectAdmin"

# Example: Pub/Sub permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/pubsub.publisher"

# Example: Cloud Logging permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/logging.logWriter"

# Example: Cloud Monitoring permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/monitoring.metricWriter"
```

### Step 3: Create Workload Identity Pool

```bash
# Create workload identity pool
gcloud iam workload-identity-pools create $POOL_ID \
    --project=$PROJECT_ID \
    --location=global \
    --display-name="OpenShift Vector Pool" \
    --description="Workload Identity Pool for Vector pods on OpenShift"
```

### Step 4: Create Workload Identity Provider

The provider configuration depends on your OpenShift setup. Here are two common scenarios:

#### Option A: OpenShift with Public OIDC Endpoint

```bash
# Get your OpenShift OIDC issuer URL
export ISSUER_URL=$(oc get authentication cluster -o jsonpath='{.spec.serviceAccountIssuer}')

# Create the provider
gcloud iam workload-identity-pools providers create-oidc $PROVIDER_ID \
    --project=$PROJECT_ID \
    --location=global \
    --workload-identity-pool=$POOL_ID \
    --issuer-uri="$ISSUER_URL" \
    --allowed-audiences="$ISSUER_URL" \
    --attribute-mapping="google.subject=assertion.sub,attribute.namespace=assertion['kubernetes.io'].namespace,attribute.service_account_name=assertion['kubernetes.io'].serviceaccount.name" \
    --attribute-condition="assertion['kubernetes.io'].namespace == '$OPENSHIFT_NAMESPACE' && assertion['kubernetes.io'].serviceaccount.name == '$OPENSHIFT_SA_NAME'"
```

#### Option B: OpenShift with Internal OIDC (requires token file projection)

For clusters without public OIDC endpoints, you'll use file-based token projection:

```bash
# Create provider for file-based tokens
gcloud iam workload-identity-pools providers create-oidc $PROVIDER_ID \
    --project=$PROJECT_ID \
    --location=global \
    --workload-identity-pool=$POOL_ID \
    --issuer-uri="https://kubernetes.default.svc.cluster.local" \
    --allowed-audiences="gcp-workload-identity" \
    --attribute-mapping="google.subject=assertion.sub"
```

### Step 5: Grant Service Account Impersonation

Allow the workload identity pool to impersonate the service account:

```bash
# Create IAM binding for service account impersonation
gcloud iam service-accounts add-iam-policy-binding $SERVICE_ACCOUNT_EMAIL \
    --project=$PROJECT_ID \
    --role="roles/iam.workloadIdentityUser" \
    --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.namespace/${OPENSHIFT_NAMESPACE}"
```

### Step 6: Generate External Account Credentials File

```bash
# Generate the credentials configuration
gcloud iam workload-identity-pools create-cred-config \
    projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID} \
    --service-account=$SERVICE_ACCOUNT_EMAIL \
    --output-file=external-account-creds.json \
    --credential-source-file=/var/run/secrets/tokens/gcp-ksa/token \
    --credential-source-type=text
```

This creates a JSON file similar to:

```json
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "file": "/var/run/secrets/tokens/gcp-ksa/token"
  },
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/SERVICE_ACCOUNT_EMAIL:generateAccessToken"
}
```

## Part 2: OpenShift Configuration

### Step 1: Create Namespace and Service Account

```bash
# Create namespace
oc new-project $OPENSHIFT_NAMESPACE

# Create service account
oc create serviceaccount $OPENSHIFT_SA_NAME -n $OPENSHIFT_NAMESPACE
```

### Step 2: Create ConfigMap with External Account Credentials

```bash
# Create ConfigMap from the credentials file
oc create configmap gcp-credentials \
    --from-file=credentials.json=external-account-creds.json \
    -n $OPENSHIFT_NAMESPACE
```

### Step 3: Create Vector Configuration

Create a Vector configuration file `vector-config.yaml`:

```yaml
# Example: GCP Cloud Storage Sink
sinks:
  gcp_cloud_storage:
    type: gcp_cloud_storage
    inputs:
      - my_source_id
    bucket: "your-gcs-bucket-name"
    credentials_path: "/etc/gcp/credentials.json"
    compression: gzip
    encoding:
      codec: json

# Example: GCP Pub/Sub Sink
sinks:
  gcp_pubsub:
    type: gcp_pubsub
    inputs:
      - my_source_id
    project: "your-gcp-project-id"
    topic: "your-topic-name"
    credentials_path: "/etc/gcp/credentials.json"
    encoding:
      codec: json

# Example: GCP Stackdriver Logs
sinks:
  stackdriver_logs:
    type: gcp_stackdriver_logs
    inputs:
      - my_source_id
    credentials_path: "/etc/gcp/credentials.json"
    log_id: "vector-logs"
    project_id: "your-gcp-project-id"
    resource:
      type: "k8s_pod"
      labels:
        project_id: "your-gcp-project-id"
        location: "us-central1"
        cluster_name: "your-cluster-name"
        namespace_name: "vector-test"
        pod_name: "{{ pod_name }}"

# Example source for testing
sources:
  demo_logs:
    type: demo_logs
    format: json
    interval: 10
```

Create the ConfigMap:

```bash
oc create configmap vector-config \
    --from-file=vector.yaml=vector-config.yaml \
    -n $OPENSHIFT_NAMESPACE
```

### Step 4: Deploy Vector with Workload Identity

Create a deployment manifest `vector-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vector
  namespace: vector-test
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vector
  template:
    metadata:
      labels:
        app: vector
    spec:
      serviceAccountName: vector
      containers:
      - name: vector
        image: timberio/vector:latest-distroless-libc
        args:
          - --config-yaml
          - /etc/vector/vector.yaml
        env:
        - name: GOOGLE_APPLICATION_CREDENTIALS
          value: /etc/gcp/credentials.json
        volumeMounts:
        - name: config
          mountPath: /etc/vector
          readOnly: true
        - name: gcp-credentials
          mountPath: /etc/gcp
          readOnly: true
        - name: gcp-token
          mountPath: /var/run/secrets/tokens/gcp-ksa
          readOnly: true
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: vector-config
      - name: gcp-credentials
        configMap:
          name: gcp-credentials
      - name: gcp-token
        projected:
          sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 3600
              audience: gcp-workload-identity
```

Deploy Vector:

```bash
oc apply -f vector-deployment.yaml
```

## Part 3: Testing and Verification

### Step 1: Verify Pod is Running

```bash
# Check pod status
oc get pods -n $OPENSHIFT_NAMESPACE

# View Vector logs
oc logs -f deployment/vector -n $OPENSHIFT_NAMESPACE
```

### Step 2: Verify Token Projection

```bash
# Check if token is being projected
POD_NAME=$(oc get pods -n $OPENSHIFT_NAMESPACE -l app=vector -o jsonpath='{.items[0].metadata.name}')

# Verify token file exists
oc exec -n $OPENSHIFT_NAMESPACE $POD_NAME -- ls -la /var/run/secrets/tokens/gcp-ksa/

# Check token content (first few characters)
oc exec -n $OPENSHIFT_NAMESPACE $POD_NAME -- head -c 50 /var/run/secrets/tokens/gcp-ksa/token
```

### Step 3: Test GCP Authentication

```bash
# Check Vector logs for authentication messages
oc logs -n $OPENSHIFT_NAMESPACE $POD_NAME | grep -i "auth\|gcp\|credential"

# Look for successful token renewal messages
oc logs -n $OPENSHIFT_NAMESPACE $POD_NAME | grep "GCP authentication token renewed"
```

### Step 4: Verify Data Flow to GCP

Depending on which sink you configured:

#### Cloud Storage Test

```bash
# List files in your GCS bucket
gsutil ls gs://your-gcs-bucket-name/

# View recent file content
gsutil cat gs://your-gcs-bucket-name/$(gsutil ls gs://your-gcs-bucket-name/ | tail -1)
```

#### Pub/Sub Test

```bash
# Create a test subscription
gcloud pubsub subscriptions create test-sub \
    --topic=your-topic-name \
    --project=$PROJECT_ID

# Pull messages
gcloud pubsub subscriptions pull test-sub \
    --limit=10 \
    --project=$PROJECT_ID \
    --auto-ack
```

#### Cloud Logging Test

```bash
# Query recent logs
gcloud logging read "logName=projects/${PROJECT_ID}/logs/vector-logs" \
    --limit=10 \
    --format=json \
    --project=$PROJECT_ID
```

#### Cloud Monitoring Test

```bash
# List custom metrics
gcloud monitoring metrics-descriptors list \
    --filter="metric.type:custom.googleapis.com" \
    --project=$PROJECT_ID
```

## Part 4: Troubleshooting

### Common Issues and Solutions

#### 1. Authentication Errors

**Error**: `Failed to get access token`

**Solutions**:
- Verify the token file exists: `oc exec $POD_NAME -- cat /var/run/secrets/tokens/gcp-ksa/token`
- Check credentials file is mounted: `oc exec $POD_NAME -- cat /etc/gcp/credentials.json`
- Verify `GOOGLE_APPLICATION_CREDENTIALS` environment variable is set correctly
- Check GCP IAM bindings are correct

#### 2. Permission Denied Errors

**Error**: `Permission denied when accessing GCS/Pub/Sub/etc`

**Solutions**:
```bash
# Verify service account has necessary roles
gcloud projects get-iam-policy $PROJECT_ID \
    --flatten="bindings[].members" \
    --format="table(bindings.role)" \
    --filter="bindings.members:serviceAccount:${SERVICE_ACCOUNT_EMAIL}"

# Add missing permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/REQUIRED_ROLE"
```

#### 3. Token Expiration Issues

**Error**: Token expired or no token renewal logs

**Solutions**:
- Check `expirationSeconds` in deployment (should be 3600 or less)
- Verify Vector is logging token renewal: `oc logs $POD_NAME | grep "token renewed"`
- Restart the pod: `oc delete pod $POD_NAME`

#### 4. Workload Identity Pool Issues

**Error**: `Invalid audience` or `workload identity pool not found`

**Solutions**:
```bash
# Verify pool exists
gcloud iam workload-identity-pools describe $POOL_ID \
    --location=global \
    --project=$PROJECT_ID

# Verify provider configuration
gcloud iam workload-identity-pools providers describe $PROVIDER_ID \
    --workload-identity-pool=$POOL_ID \
    --location=global \
    --project=$PROJECT_ID
```

### Debug Mode

Enable debug logging in Vector:

```yaml
# Add to vector.yaml
api:
  enabled: true
  address: "0.0.0.0:8686"

# Set log level
[sources.internal_metrics]
type = "internal_metrics"

[sinks.console]
type = "console"
inputs = ["internal_metrics"]
encoding.codec = "json"
target = "stdout"
```

Then check detailed logs:

```bash
oc logs -f $POD_NAME -n $OPENSHIFT_NAMESPACE
```

### Testing Authentication Manually

You can test the authentication flow manually using `curl`:

```bash
# Get the projected token
TOKEN=$(oc exec $POD_NAME -- cat /var/run/secrets/tokens/gcp-ksa/token)

# Exchange for GCP access token
curl -X POST https://sts.googleapis.com/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "audience=//iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "scope=https://www.googleapis.com/auth/cloud-platform" \
  -d "subject_token=${TOKEN}"
```

## Part 5: Alternative Testing Methods

### Method 1: Using Service Account Keys (For Testing Only)

If Workload Identity setup is complex, you can test with service account keys first:

```bash
# Create a key (NOT RECOMMENDED FOR PRODUCTION)
gcloud iam service-accounts keys create sa-key.json \
    --iam-account=$SERVICE_ACCOUNT_EMAIL \
    --project=$PROJECT_ID

# Create secret
oc create secret generic gcp-sa-key \
    --from-file=key.json=sa-key.json \
    -n $OPENSHIFT_NAMESPACE

# Update Vector deployment to use the key
# In vector-deployment.yaml, change credentials path:
# - name: GOOGLE_APPLICATION_CREDENTIALS
#   value: /etc/gcp/key.json
```

### Method 2: Using API Keys (For Public APIs Only)

For certain GCP services, you can use API keys:

```bash
# Create an API key in GCP Console or:
gcloud services api-keys create \
    --display-name="Vector Test Key" \
    --project=$PROJECT_ID

# Configure Vector with api_key instead of credentials_path
# In vector.yaml:
# sinks:
#   gcp_cloud_storage:
#     api_key: "your-base64-encoded-api-key"
```

## Part 6: Performance Testing

### Load Testing Vector with GCP Sinks

Create a load test configuration:

```yaml
sources:
  load_test:
    type: demo_logs
    format: json
    interval: 0.1  # 10 messages per second per replica
    count: 1000

sinks:
  gcp_test:
    type: gcp_cloud_storage
    inputs: ["load_test"]
    bucket: "your-test-bucket"
    credentials_path: "/etc/gcp/credentials.json"
    compression: gzip
    batch:
      max_events: 1000
      timeout_secs: 10
```

Scale the deployment:

```bash
oc scale deployment vector --replicas=3 -n $OPENSHIFT_NAMESPACE
```

Monitor performance:

```bash
# Watch pod metrics
oc adm top pods -n $OPENSHIFT_NAMESPACE

# Check Vector internal metrics
oc port-forward deployment/vector 8686:8686 -n $OPENSHIFT_NAMESPACE
# Then visit http://localhost:8686/metrics
```

## Summary Checklist

- [ ] GCP project and service account created
- [ ] Workload Identity Pool and Provider configured
- [ ] Service account impersonation permissions granted
- [ ] External account credentials file generated
- [ ] OpenShift namespace and service account created
- [ ] Token projection configured in deployment
- [ ] Vector configuration created with GCP sinks
- [ ] Vector pod running successfully
- [ ] Authentication working (check logs)
- [ ] Data flowing to GCP services verified
- [ ] Token renewal working (check logs over time)

## Additional Resources

- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [OpenShift Service Account Tokens](https://docs.openshift.com/container-platform/latest/authentication/bound-service-account-tokens.html)
- [Vector GCP Sinks Documentation](https://vector.dev/docs/reference/configuration/sinks/)
- [google-cloud-auth Rust Crate](https://docs.rs/google-cloud-auth/)

## Support

For issues with:
- **Vector GCP authentication**: Check Vector logs and verify credentials file format
- **GCP permissions**: Use `gcloud` commands to verify IAM policies
- **OpenShift token projection**: Check pod events and service account configuration
- **Network connectivity**: Ensure pods can reach GCP APIs (check firewall rules)
