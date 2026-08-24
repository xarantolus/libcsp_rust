# Golden-vector oracle

`gen_vectors.c` drives the real libcsp API and records **what actually lands on the
wire**, so the Rust ports are diffed against observed behaviour rather than against a
reading of the C source.

Packets are sent through a capture interface whose `nexthop` copies
`frame_begin[0..frame_length]` — that is the real frame, after `csp_id_prepend`, after
SFP headers are appended, after CFP fragmentation.

## Generating

```sh
cmake -S libcsp -B build/canonical -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
  -DCSP_USE_RDP=ON -DCSP_USE_HMAC=ON -DCSP_USE_PROMISC=ON -DCSP_USE_RTABLE=ON \
  -DCSP_HAVE_STDIO=ON -DCSP_ENABLE_CSP_PRINT=ON -DCSP_PRINT_STDIO=ON \
  -DCSP_BUFFER_ZERO_CLEAR=ON -DCSP_ENABLE_KISS_CRC=ON
ninja -C build/canonical

cc -o build/gen_vectors oracle/gen_vectors.c \
  -Ilibcsp/include -Ibuild/canonical/include -Ilibcsp/src \
  -Lbuild/canonical -lcsp -Wl,-rpath,$PWD/build/canonical -lpthread

./build/gen_vectors 1 vectors/v1.tsv
./build/gen_vectors 2 vectors/v2.tsv
```

The generator asserts its own buffer accounting and **exits non-zero if it leaks**, so a
regression in the C cannot quietly corrupt the vectors.

## Format

Tab-separated triples, one per line:

```
<kind>	<input description>	<output hex>
```

`kind` is the vector family (`id_v1`, `cfp_v2`, `sha1`, …). `input description` is a
comma-separated `key=value` list the Rust side parses to reconstruct the input.

## One process per wire version — not optional

`csp_conf.version` **must not change after `csp_init()`**. `host_bits` (5 for v1, 14 for
v2) is baked into the routing and broadcast maths at init, so flipping the version
afterwards misroutes every packet into the qfifo, where nothing drains it.

Measured while building this: 18/18 SFP sends clean under v1, then the same 18 sends
after switching to v2 leak **one buffer per fragment** until the pool is empty and every
call returns `CSP_ERR_NOMEM`. No error is reported at the point of misuse, and nothing in
the API marks the field as init-only. See `SCOPE.md` deviation 9.

## What is deliberately not here

**RDP.** Its initial sequence number is not deterministic, so byte-exact golden vectors
are the wrong tool. RDP is covered by a trace-differential test that drives identical
scripted packet sequences through the C and the Rust state machine and compares the
emitted frames.

**Uptime / memfree service replies.** They carry live values. Only the reply *shape* is
recorded.

**YAML.** libyaml is not installed in this environment, so `csp_yaml.c` is not in the
build. The Rust parser is tested against the format rather than differentially.
