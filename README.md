# Cert-Manager: DNSMadeEasy DNS-01 Webhook

- k8s 1.30+
- go 1.22
- alpine 3.19
- supports testing against DME sandbox API

## Credentials

### Storage

I'm not a big fan of duplicating DNS API credentials into vanilla kubernetes secrets and widening the webhook service account RBAC. As such, this webhook is scaffolded to optionally inject secrets as environment variables from an azure vault using [AKV2K8S](https://akv2k8s.io/). Other vault services (hashicorp, ...CSPs) are supported with minor chart adjustments.

The webhook will first attempt loading credentials from environment variables if `azureKeyVault.enabled`, then attempt retrieving a secret if `secretRef.enabled`. At least one mode should be enabled.

#### Vanilla K8S Secrets

Should `secretRef.enabled=true`, issuer config may be defined as:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
......
- dns01:
    webhook:
      groupName: acme.example.com
      solverName: dme
      config:
        apiKeyRef:
          name: dme-credentials
          key: key
        apiSecretRef:
          name: dme-credentials
          key: secret
        ttl: 600
```

### External Vault

Should `azureKeyVault.enabled=true`, chart values should be defined as:

```yaml
azureKeyVault:
  # ensure namespace has label: 'azure-key-vault-env-injection: enabled'
  # https://akv2k8s.io/security/enable-env-injection/
  enabled: true
  secrets:
    apiSecret:
      vaultName: example-azure-vault
      vaultObjectName: dme-credentials
      envVarName: DME_API_SECRET
      reflect: false
    apiKey:
      vaultName: example-azure-vault
      vaultObjectName: dme-credentials
      envVarName: DME_API_KEY
      reflect: false
```

... and issuers may be defined as:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
......
- dns01:
    webhook:
      groupName: acme.example.com
      solverName: dme
      config:
        apiKeyenvVar: DME_API_KEY
        apiSecretenvVar: DME_API_SECRET
        ttl: 600
```

### Sharing

Another common design pattern I implement is centered around reflecting TLS secrets. This helps to honor rate-limiting constraints and stay organized:

- define all your certificates in one namespace (typically `cert-manager`)
- leverage a reflection tool such as [reflector](https://github.com/emberstack/kubernetes-reflector) to mirror TLS secrets across other namespaces for workload consumption

Annotate certificates for reflector:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: star-grug-io-staging
  namespace: cert-manager
spec:
  dnsNames:
    - "*.grug.io"
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: example-issuer
  secretName: star-grug-io-staging-tls
  secretTemplate:
    annotations:
      reflector.v1.k8s.emberstack.com/reflection-allowed: "true"
      reflector.v1.k8s.emberstack.com/reflection-auto-enabled: "true"
      reflector.v1.k8s.emberstack.com/reflection-auto-namespaces: sdfhkf2,KH82bs,DHYJgv8
```

## Quick Setup

populate `./testdata` (see `./testdata/README.md`)

check tests

```bash
TEST_ZONE_NAME=grug.io. DNS_SERVER=ns1.sandbox.dnsmadeeasy.com:53 DME_BASE_URL=https://api.sandbox.dnsmadeeasy.com/V2.0 make test
```

build image

```bash
make build
```

render & verify helm template

```bash
make rendered-manifest.yaml
```

## Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

**It is essential that you configure and run the test suite when creating a
DNS01 webhook.**

You can run the test suite with:

```bash
$ TEST_ZONE_NAME=grug.io. DNS_SERVER=ns1.sandbox.dnsmadeeasy.com:53 DME_BASE_URL=https://api.sandbox.dnsmadeeasy.com/V2.0 make test
```

## Logging

- `-v=2` will print basic details on challenges, cleanup, and response status
- `-v=3` will print debug details including response bodies
