# Rate limiting

Rate limits are configured per server (`rate_limit: "5/minute"` on a server's policy) and
answer *how fast* a caller may call. They are a different control from
[quotas](quotas.md), which answer *how much, over a billing period* — see that page for the
distinction and why the two behave differently under failure.

## Backends

| Backend | Setting | Use when |
|---|---|---|
| In-memory (default) | `ACROPOLIS_RATE_LIMIT_BACKEND=memory` | One replica. Correct and requires nothing extra. |
| Valkey/Redis | `ACROPOLIS_RATE_LIMIT_BACKEND=valkey` | More than one replica. Required — see below. |

### Why the backend matters once you scale out

The in-memory backend keeps token buckets in the gateway process's own memory. That is exactly
right for a single replica and costs nothing.

With N replicas it is **wrong in a way that is silent**: each replica holds its own full copy of
every bucket, so a limit configured as `100/minute` permits up to `100 × N` per minute in
practice, and which limit any given client experiences depends on which replica the load
balancer routed them to. Nothing logs this and no metric shows it — the policy page keeps
displaying `100/minute`.

This is why `deploy/k8s/deployment.yaml` pins `replicas: 1`. Do not raise it while using the
in-memory backend.

## Running the Valkey backend

Install the optional extra (the client is not in the base install, since a single-replica
deployment should not have to carry it):

```bash
pip install 'acropolis[distributed]'
```

Point it at a Valkey or Redis server:

```bash
ACROPOLIS_RATE_LIMIT_BACKEND=valkey
ACROPOLIS_RATE_LIMIT_BACKEND_URL=redis://valkey:6379/0
```

`deploy/docker-compose.yml` has a commented-out `valkey` service and the matching environment
variables — uncomment both together.

Either server works: the client speaks one wire protocol and this project's compose file and
test suite use [Valkey](https://valkey.io) (BSD-licensed, the maintained fork since Redis's 2024
license change). A `redis://` URL is correct for both; that is the protocol scheme, not a
statement about which server you run.

### Misconfiguration fails at startup

An unknown backend name, or `valkey` without a URL, raises at boot rather than at request time.
That is deliberate given the failure posture below — an operator who typos the setting should
find out from a failed startup, not from a support ticket.

### Persistence is not needed

The commented compose service disables saving (`--save "" --appendonly no`). Rate-limit buckets
are ephemeral by design: losing them on restart refills every bucket to full, which is a brief
under-enforcement, not corruption. Persistence would add disk I/O on the request hot path and
buy nothing.

## What happens when the backend is unreachable

**Rate limiting fails closed.** If the gateway cannot reach Valkey, affected requests are
refused with `429`, not allowed through.

This is deliberate, and it is the opposite of how [quotas](quotas.md) behave (quota checks fail
*open* — a database hiccup lets the call proceed). The reasoning:

A rate limiter exists specifically to resist an adversary generating load. If it failed open,
an adversary would not need to defeat the limiter at all — they would only need to make the
shared backend unavailable (contend it into timeouts, partition the network, exhaust its
connections), and every replica would fall open at once. That is a strictly easier attack than
the one the limiter is meant to stop, and the load required to mount it is exactly the resource
a rate-limit-evading attacker already has.

The same reasoning already governs `block_pattern` policy rules, which treat an undetermined
match as a block for the identical reason (see [policy cookbook](policy-cookbook.md)).

**The cost, stated plainly:** a Valkey outage that would have been invisible under a fail-open
design instead surfaces as 429s. That is the correct trade for a security control, and it is
loud rather than a silent bypass — but it does mean **the Valkey server is on the critical path
for every rate-limited request**, and should be monitored and resourced accordingly.

### Telling the two apart in the audit log

A refusal caused by the backend being down is recorded with `rule = rate_limit_backend_unavailable`,
distinct from a genuine over-limit refusal (`rule = rate_limit`). A spike of the former means go
look at Valkey; a spike of the latter means the configured limit is doing its job.

## Behaviour is identical across backends

A spec like `5/minute` means the same thing in both backends — same continuous-refill token
bucket, same cap, same consume-one-per-call. The Valkey backend runs that algorithm as a single
atomic server-side script rather than a read-then-write from the client, so concurrent callers
across replicas cannot race past the limit between the read and the write. Switching backends
changes where the state lives, not what a limit means.
