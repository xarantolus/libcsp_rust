# Per-function audit

One section per module. Each records what was checked against the C, whether the port is
**faithful** (same observable behaviour, deviations recorded in `SCOPE.md`) and whether it
is **rusty** (an API a Rust caller would want, not a transliteration), plus anything found
and what was done about it.

Where a divergence is deliberate it points at the `SCOPE.md` entry. Nothing here is filed
upstream.

Status key: ✅ done · 🔶 partial · ❌ missing

---

## `csp-core::id` — header codec

Against `src/csp_id.c` (15 functions).

| C | Rust | |
|---|---|---|
| `csp_id1_prepend` / `csp_id2_prepend` | `Id::encode` | ✅ |
| `csp_id1_extract` / `csp_id2_extract` | `Id::decode` | ✅ |
| `csp_id_prepend` / `csp_id_extract` (version dispatch) | `Version` parameter | ✅ |
| `csp_id_strip` | `Packet::set_frame` | ✅ length check included |
| `csp_id1_setup_rx` / `csp_id2_setup_rx` | `Packet::set_frame` | ✅ different shape, same job |
| `csp_id_get_host_bits` / `max_nodeid` / `max_port` / `header_size` | `Version` methods | ✅ |
| `csp_id_is_broadcast` | `Version::is_broadcast` | ✅ plus a shift guard |
| `csp_id_prepend_fixup_cspv1` and the two siblings | — | ❌ **out of scope** |

**The `_fixup_cspv1` trio is out of scope, verified not assumed.** They swap CSP v1 headers
to little-endian, and `grep` across `src/` shows the only callers are
`csp_if_zmqhub.c:88,137`. ZMQ is out of scope (`SCOPE.md`), so these go with it. Recorded
here because "we didn't port three public functions" should not be something a reader has
to discover.

**Faithful:** yes. Verified beyond reading — the differential suite runs encode over every
in-range id and decode over **every bit pattern** in both versions, ~300k inputs per run,
byte-identical. `is_broadcast` is also differentially tested across random
address/netmask combinations.

**Rusty:** yes. `Version` is a parameter rather than a global, which is what makes the
`csp_conf.version`-after-init leak (`SCOPE.md` 13) unrepresentable. `encode` validates
field widths instead of shifting an oversized value into its neighbour (`SCOPE.md` 7).

**Deviations:** `SCOPE.md` 7 (field validation), 13 (immutable version).

**Found during the audit:** nothing wrong; four coverage gaps, now tested — encoding into
an oversized buffer must not clobber past the header, decoding must ignore trailing
payload bytes, the flags field is 8 bits in v1 and 6 in v2, and broadcast detection across
every netmask rather than only the all-ones case. 11 tests → 16.
