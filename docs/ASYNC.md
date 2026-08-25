# Sketch: a sync and an async shell over the same core

**Not implemented.** This is the shape the work would take, written down while the
reasoning is fresh. Nothing here is in the crate.

## Why it is a small question rather than a large one

The usual reason a library cannot offer both is that its I/O is baked into its logic — the
protocol code calls `read()` somewhere in the middle, and turning that into `.await`
colours every function above it. That is what the sans-io split already prevents:

- `csp-core` performs **no I/O and reads no clock**. Every state machine is stepped by the
  caller, who supplies the bytes and the time. There is nothing in it to make async.
- `csp` owns the buffer pool, connections and routing, and still performs no I/O: it
  returns `Outbound::Transmit { iface, via, packet }` and expects the caller to move the
  bytes.

So neither crate needs an async variant. The question is only what the *outermost* layer
looks like — the loop that waits for a packet — and that layer is thin.

## The shape

Two shells, one core, sharing everything below them:

```
   csp-sync                       csp-async
   ├ blocking Transmit            ├ async Transmit
   ├ accept() blocks on a condvar ├ accept().await
   └ a thread runs work()         └ a task runs work()
                    \            /
                     csp  (Node, Pool, Router)      <- no I/O, no async
                     csp-core (codecs, RDP, SFP)    <- no I/O, no clock
```

The convention Rust has settled on for this is **duplicate the thin layer, share the
thick one**. `embedded-hal` / `embedded-hal-async` do it, as do `postgres` /
`tokio-postgres` and `ureq` / `reqwest`. The alternative — one generic layer abstracting
over sync and async — is what the ecosystem has repeatedly tried and abandoned; see below.

## What each shell owns

Only three things in the whole surface actually block:

| Operation | Sync | Async |
|---|---|---|
| Wait for a connection | `accept_timeout(d) -> Option<Handle>` | `accept().await` |
| Wait for a packet on one | `read_timeout(c, d)` | `read(c).await` |
| Hand bytes to a driver | `fn transmit(&mut self, …) -> Result<()>` | `async fn transmit(…)` |

Everything else — `bind`, `connect`, `send`, `route_set`, `work`, `tick`, the whole of
`csp-core` — is already non-blocking and is used **unchanged** by both. `Node::accept`
already returns `Option<Handle>` rather than blocking, which is exactly the primitive both
shells need: the sync shell parks on a condvar and retries, the async shell registers a
waker and retries.

`transmit` is the one that genuinely has to be written twice, because an async trait
method is a different trait. It is a one-method trait, so the duplication is one method.

## The piece that needs care

`Packet` is an RAII handle onto a pool slot and releases on `Drop`. In the async shell a
task holding one can be cancelled at any `.await`, so the guarantee to check is that
**cancellation at any await point releases every packet the task held**. Drop gives that
for free as long as no packet is ever parked in a `static` or a detached structure across
an await — which is a rule to state and test, not a design problem. The obvious test is
the one already written for the sync side: a pool-accounting assertion around an operation
that fails partway, extended to an operation that is dropped partway.

RDP is the other thing worth naming, and it is fine: it reads no clock and holds no timer.
A retransmission is something `tick(now_ms)` returns, so the async shell schedules it on a
timer of its choosing and the sync shell calls `tick` from its loop. Neither needs the
core to know which it is.

## What this deliberately does not do

**No `maybe-async` macro, no `#[cfg(feature = "async")]` on the core.** A crate whose
public API changes shape with a feature flag cannot be depended on by two crates in one
graph, and Cargo unifies features across a build — so one dependency turning on `async`
silently changes the API another dependency compiled against. This is the failure mode
that made the ecosystem stop trying.

**No generic `trait Executor` abstraction over both.** It is expressible and it is worse
than the duplication: every signature grows a parameter, every error message doubles in
length, and the shared code was three functions to begin with.

## Cost

Two thin crates, an `async fn transmit`, and a cancellation test. The reason it is this
small is the decision made at the start — that `csp-core` would take the clock as an
argument and `csp` would return its outbound packets rather than sending them. That was
made to keep the port testable without a scheduler. Making both shells possible is a
side effect of it, and it is the strongest argument for the sans-io shape that this
project produced.
