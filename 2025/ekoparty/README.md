# Ingress Nightmare PoC

> Built on CVE-2025-1097 and CVE-2025-1974

Minimal PoC of the NGINX Ingress issue using Go tests and Testcontainers on top of k3s.

```mermaid
flowchart TD
  A[go test] --> B[Start k3s with Testcontainers]
  B --> C[Deploy NGINX Ingress, demo app and TLS secret]
  C --> D[Port-forward HTTP and HTTPS locally]
  D --> E[Send exploit payload to NGINX]

  E --> F{Mode}
  F -->|Monitoring| G[Helper pod watches /proc in nginx to detect pid/fd]
  F -->|Brute force| H[Workers guess pid/fd via HTTPS requests]

  G --> I[Build AdmissionReview with detected pid/fd]
  H --> I[Build AdmissionReview with guessed pid/fd]

  I --> J[Send AdmissionReview to ingress-nginx admission webhook]
  J --> K[nginx loads poc.so from testdata]
  K --> L[Test confirms code execution]
```

## Requirements

* Go
* Docker running (needed by Testcontainers)

## Monitoring mode (default)

```bash
go test -v -run TestPoC .
```

* Spins up k3s + NGINX Ingress.
* Uses an in-cluster helper to inspect `/proc` in the nginx pod and detect `pid/fd`.
* Builds and sends a single exploit AdmissionReview with the correct values.

Fast and reliable, but not a realistic attacker view (extra `/proc` visibility).

## Brute force mode

```bash
BRUTE_FORCE=true go test -v -run TestPoC .
```

Same scenario, but:

* Only interacts over HTTP/HTTPS.
* Brute-forces the `pid/fd` pair.
* Slower and **not fully tested**, so it may timeout or fail.
