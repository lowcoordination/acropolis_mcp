# Kubernetes manifests

Generic manifests for running Acropolis on any Kubernetes cluster — no assumptions about a
specific cloud provider, ingress controller, or storage class. If you just want to try Acropolis
quickly, [docker compose](../docker-compose.yml) is the faster path; use these if you're
already running workloads on Kubernetes and want Acropolis alongside them.

## Before you apply

1. **Have a Postgres instance ready.** Acropolis requires Postgres (enterprise #7, issue #8) —
   there is no bundled database in this manifest set. See
   [docs/postgres.md](../../docs/postgres.md) for what's needed (a managed instance like RDS/
   Cloud SQL, or a Postgres you already run in-cluster both work).
2. **Build and push the image** somewhere your cluster can pull it from (a registry you
   control — Docker Hub, GHCR, a self-hosted registry). The repo root's `Dockerfile` builds
   it; there's no published image to pull as-is yet.
3. **Edit `deployment.yaml`**: replace the `image:` field with your pushed image.
4. **Create the database Secret** (namespace must exist first — see apply order below):
   ```bash
   kubectl -n acropolis create secret generic acropolis-db \
     --from-literal=url='postgresql://user:pass@host:5432/acropolis'
   ```
5. Decide how you'll reach Acropolis — a `ClusterIP` Service plus `kubectl port-forward` for a
   quick look, an `Ingress` (see `ingress.yaml.example`) for a real hostname with TLS, or
   `type: LoadBalancer` in `service.yaml` if your cluster provisions external IPs.

## Apply order

```bash
kubectl apply -f namespace.yaml
kubectl -n acropolis create secret generic acropolis-db \
  --from-literal=url='postgresql://user:pass@host:5432/acropolis'
kubectl apply -f configmap.yaml
kubectl apply -f pvc.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

The Secret has to exist before `deployment.yaml` (the Deployment references it via
`secretKeyRef`), and the namespace has to exist before the Secret — the rest can go in any
order, but applying in this sequence avoids Kubernetes rejecting a manifest whose namespace
isn't there yet.

Confirm it came up:

```bash
kubectl -n acropolis get pods
kubectl -n acropolis port-forward svc/acropolis 8000:8000
```

Then open `http://localhost:8000` and finish setup, same as the
[quickstart](../../docs/quickstart.md).

## Building and rolling out a new image

There is no CI image publish, so a release is built by hand from a **merged** commit. This is the
procedure used for 0.1.8; every step below was run.

1. **Pick the commit and see what goes out with it.** Everything merged since the last build ships,
   not only your change:
   ```bash
   git log --oneline <previous-build-commit>..<commit>
   ```
   0.1.8 carried a gateway behaviour change (#167) alongside the change it was built for. Read
   that list before building.
2. **Build from a clean archive, not your working tree.** Untracked and local files must not
   reach the image:
   ```bash
   B=$(mktemp -d) && git archive <commit> | tar -x -C "$B" && cd "$B"
   docker build -t <registry>/acropolis:<version> .
   ```
   Versions are never reused. List the registry's tags first
   (`curl -s https://<registry>/v2/<repo>/tags/list`) and take the next one.
3. **Push, then read the digest back from the registry** rather than trusting your local copy:
   ```bash
   docker push <registry>/acropolis:<version>
   curl -sI -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json" \
     https://<registry>/v2/<repo>/manifests/<version> | grep -i docker-content-digest
   ```
   The digest must equal the one `docker push` printed.
4. **Pin the manifest by tag and digest** in `deployment.yaml`:
   `image: <registry>/acropolis:<version>@sha256:<digest>`. The tag is for people; the digest is
   what the cluster enforces. Put the source commit in a comment next to it. Then validate:
   ```bash
   kubectl apply --dry-run=server -f deployment.yaml
   ```
5. **Change the manifest through review, then apply after it merges.** Cluster manifests are
   security-relevant, so the change gets a code review and a security scan like any other.
6. **Apply and verify what is actually running**, not that the command succeeded:
   ```bash
   kubectl apply -f deployment.yaml
   kubectl -n acropolis rollout status deploy/acropolis
   kubectl -n acropolis get pod -l app=acropolis \
     -o jsonpath='{.items[*].status.containerStatuses[0].imageID}'   # must contain the new digest
   kubectl -n acropolis logs deploy/acropolis | grep -i -E "error|traceback"
   curl -s https://<your-host>/api/v1/health                          # {"status":"ok"}
   ```
   Then exercise whatever the release changed with a real call through the gateway; health
   checks alone do not prove client traffic still works. A fresh pod sees no client requests
   until a client next calls, so a quiet log is not evidence.
7. **Rollback** is re-applying the previous `image:` line. Old tags stay in the registry, which is
   why they are never reused.

Test on the Python the image ships (see the `Dockerfile` base), not only your development one:
a TLS-trust bug in 0.1.8 passed on Python 3.14 and was caught only by CI on 3.12.

## What's in here

| File | Purpose |
|---|---|
| `namespace.yaml` | The `acropolis` namespace everything else lives in. |
| `configmap.yaml` | Non-secret env vars (`auth_mode` default, host/port). |
| `pvc.yaml` | 1Gi persistent volume for non-database on-disk state (see `pvc.yaml`'s own comment — config and audit log live in Postgres now, not on this volume). |
| `deployment.yaml` | Deployment (1 replica by default — see `deployment.yaml`'s comment on raising it). Non-root, resource limits, liveness/readiness probes on `/api/v1/health`. |
| `service.yaml` | `ClusterIP` by default; comments show how to switch to `LoadBalancer`. |
| `ingress.yaml.example` | A worked Ingress + cert-manager example — copy to `ingress.yaml` and fill in your hostname/issuer before applying. |

## Replica count

Running more than one replica is supported, with **one hard prerequisite**.

### Required first: a shared rate-limit backend

Set `ACROPOLIS_RATE_LIMIT_BACKEND=valkey` (and `ACROPOLIS_RATE_LIMIT_BACKEND_URL`) before
raising `replicas`. See [docs/rate-limiting.md](../../docs/rate-limiting.md).

The default backend keeps token buckets in process memory, so N replicas would enforce N
independent copies of every configured limit — a policy set to 100/minute actually allowing
100×N/minute. Nothing surfaces that when it happens: no log line, no metric, and the policy page
still shows the configured value. It is a silent bypass of a security control, which is why this
prerequisite is not optional.

`deployment.yaml` ships `replicas: 1` because that is the correct **default** for a deployment
that hasn't configured Valkey — which is every deployment out of the box. It is a default, not a
prohibition.

### Also size for the replica count

Keep `N × (ACROPOLIS_DB_WRITER_POOL_MAX + ACROPOLIS_DB_READER_POOL_MAX)` under Postgres's
`max_connections` — see [docs/postgres.md](../../docs/postgres.md).

### Two behaviours change (neither blocks scaling)

- **Webhook threshold alerts can fire up to once per replica** rather than exactly once. The
  debounce and threshold-fired state in `stoa/webhooks.py` is per-process.
- **Every replica runs its own health poller**, multiplying upstream probe traffic by the
  replica count.

Both are covered in docs/rate-limiting.md's "What changes when you run more than one replica".

**Quota enforcement is not affected** — both halves of its window live in shared Postgres, so a
quota of 1000/month stays 1000/month across the fleet. See
[docs/quotas.md](../../docs/quotas.md).

### History

Pre-Postgres-cutover this was capped at 1 for a *different* reason — SQLite's single-writer
model, with `strategy: Recreate` guaranteeing one pod touched the on-disk files at a time.
Postgres (enterprise #7, issue #8) removed that constraint; concurrent writers are now
Postgres's job.

When #31 lands, size Postgres's `max_connections` and this app's own pool settings for the
replica count you want — see [docs/postgres.md](../../docs/postgres.md).

## Secrets

Two things need a Secret; this repo doesn't create either for you:

- **`acropolis-db`** (required): `ACROPOLIS_DATABASE_URL`, wired via the `acropolis-db` Secret's
  `url` key — see "Before you apply" above for the `kubectl create secret` command. There's no
  bundled Postgres StatefulSet in this manifest set; point it at a managed instance (RDS,
  Cloud SQL, ...) or a Postgres you already run elsewhere in-cluster.
- **`acropolis-admin-token`** (optional): a bearer-token override for automation that bypasses
  the browser login flow — see the commented-out block in `deployment.yaml` if you need it.

Everything else (the admin password itself) is set through the web UI's first-run wizard and
stored, hashed, in Postgres — not as a Kubernetes Secret.
