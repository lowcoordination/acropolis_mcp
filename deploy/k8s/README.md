# Kubernetes manifests

Generic manifests for running Argus on any Kubernetes cluster — no assumptions about a
specific cloud provider, ingress controller, or storage class. If you just want to try Argus
quickly, [docker compose](../docker-compose.yml) is the faster path; use these if you're
already running workloads on Kubernetes and want Argus alongside them.

## Before you apply

1. **Build and push the image** somewhere your cluster can pull it from (a registry you
   control — Docker Hub, GHCR, a self-hosted registry). The repo root's `Dockerfile` builds
   it; there's no published image to pull as-is yet.
2. **Edit `deployment.yaml`**: replace the `image:` field with your pushed image.
3. Decide how you'll reach Argus — a `ClusterIP` Service plus `kubectl port-forward` for a
   quick look, an `Ingress` (see `ingress.yaml.example`) for a real hostname with TLS, or
   `type: LoadBalancer` in `service.yaml` if your cluster provisions external IPs.

## Apply order

```bash
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f pvc.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

Or all at once now that they're in dependency-safe order:

```bash
kubectl apply -f namespace.yaml -f configmap.yaml -f pvc.yaml -f deployment.yaml -f service.yaml
```

Confirm it came up:

```bash
kubectl -n argus get pods
kubectl -n argus port-forward svc/argus 8000:8000
```

Then open `http://localhost:8000` and finish setup, same as the
[quickstart](../../docs/quickstart.md).

## What's in here

| File | Purpose |
|---|---|
| `namespace.yaml` | The `argus` namespace everything else lives in. |
| `configmap.yaml` | Non-secret env vars (`auth_mode` default, host/port). |
| `pvc.yaml` | 1Gi persistent volume for the SQLite config + audit databases. |
| `deployment.yaml` | Single-replica Deployment. Non-root, resource limits, liveness/readiness probes on `/api/v1/health`. |
| `service.yaml` | `ClusterIP` by default; comments show how to switch to `LoadBalancer`. |
| `ingress.yaml.example` | A worked Ingress + cert-manager example — copy to `ingress.yaml` and fill in your hostname/issuer before applying. |

## Why only one replica

Argus stores its config and audit log in SQLite on a single `ReadWriteOnce` volume. Running
more than one replica would mean two processes writing the same SQLite files, which isn't
safe. The Deployment uses `strategy: Recreate` for the same reason — a rolling update would
briefly run two pods against the same volume otherwise. If you outgrow this (very high audit
volume, need for horizontal scaling), that's a real architectural change, not a config
tweak — open an issue if you're hitting that ceiling.

## Secrets

There's no Secret manifest here because there's nothing that requires one by default — the
admin password is set through the web UI's first-run wizard and stored (hashed) in the SQLite
database on the PVC, not as a Kubernetes Secret. The one exception is `ARGUS_ADMIN_TOKEN`, an
optional bearer-token override for automation that bypasses the browser login flow — see the
commented-out block in `deployment.yaml` if you need it; wire it to a real Secret rather than
putting it in the ConfigMap.
