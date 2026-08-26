"""Break the port on purpose; count which corpus records notice.

`just corpus` says how many records exist. That is not the same as how many *measure*
anything: a replay that never calls into `csp`/`csp_core`, or that records too little to
distinguish two behaviours, passes whatever the port does while still counting itself.

Both have happened here. A `diverges` verdict compared JSON objects with different key sets
and so could not fail; a replay arm returned a hardcoded copy of the C's own answer; and
nine security records reported only "a packet arrived", which is identical whether the
policy verified it or never ran.

So each mutation below disables one guard the port is supposed to have, and the run reports
how many records fail as a result. **A mutation nothing notices is a hole**, either in what
the C suite exercises or in what the records observe. This is the only check for that class
which does not rely on reading the tests and believing them.

Usage: `just mutants`. Each mutation is applied and reverted in turn; a crash mid-run leaves
the tree dirty, so check `git status` if it is interrupted.
"""

import pathlib, re, subprocess

MUTANTS = [
  ("cmp: request length gate", "csp-core/src/cmp.rs",
   "    if data.len() < request_len(h.code) {", "    if false {"),
  ("cmp: POKE carries its data", "csp-core/src/cmp.rs",
   "    if present != declared as usize {", "    if false {"),
  ("cmp: peek tail zeroed", "csp-core/src/cmp.rs",
   "pub const TAIL_LEN: usize = 3;", "pub const TAIL_LEN: usize = 0;"),
  ("eth: zero-length segment", "csp-core/src/eth.rs",
   "        if h.seg_size == 0 {", "        if false {"),
  ("eth: running total bound", "csp-core/src/eth.rs",
   "        if self.received as usize + payload.len() > self.total as usize {", "        if false {"),
  ("eth: declared-length floor", "csp-core/src/eth.rs",
   "                if h.packet_length < self.min_len {", "                if false {"),
  ("eth: buffer bound up front", "csp-core/src/eth.rs",
   "                if h.packet_length as usize > out.len() {", "                if false {"),
  ("dedup: mode applies", "csp/src/dedup.rs",
   "            DedupMode::Forwarded => !to_me,", "            DedupMode::Forwarded => false,"),
  ("dedup: duplicate detection", "csp/src/router.rs",
   "            if framed.with_frame(|f| self.dedup.is_duplicate(f, now_ms)) {", "            if false {"),
  ("rdp: nothing-to-ack guard", "csp-core/src/rdp.rs",
   "        if self.rcv_cur == self.rcv_lsa {", "        if false {"),
  ("rdp: delay-count boundary", "csp-core/src/rdp.rs",
   "        outstanding as u32 > self.opts.ack_delay_count",
   "        outstanding as u32 >= self.opts.ack_delay_count"),
  ("sfp: shape classification", "csp/src/delivery.rs",
   "        if first.id().is_fragment() {", "        if true {"),
  ("conn: table exhaustion frees", "csp/src/router.rs",
   "                        return Routed::Dropped(DropReason::ConnectionTableFull);",
   "                        core::mem::forget(packet);\n                        return Routed::Dropped(DropReason::ConnectionTableFull);"),
  ("conn: announced only once", "csp/src/router.rs",
   "                if is_new {\n                    self.queue_accept(handle);\n                }",
   "                self.queue_accept(handle);"),
  ("route: fan-out to every match", "csp/src/router.rs",
   "                Some(c) => self.push_pending(iface, via, c.into_index()),",
   "                Some(_c) => {}"),
  ("promisc: tap runs at all", "csp/src/router.rs",
   "        if self.promisc_enabled {", "        if false {"),
  ("promisc: tap sees forwarded", "csp/src/router.rs",
   "        if self.promisc_enabled {", "        if self.promisc_enabled && for_us {"),
  ("security: whole policy", "csp-core/src/security.rs",
   "    let mut body = payload;", "    let mut body = payload;\n    if true { return Ok(body); }"),
]

for name, path, old, new in MUTANTS:
    p = pathlib.Path(path)
    orig = p.read_text()
    if old not in orig:
        print(f"{name:34s} MUTATION DID NOT APPLY -- pattern gone")
        continue
    p.write_text(orig.replace(old, new, 1))
    r = subprocess.run(["cargo","test","-p","csp","--all-features","--test","corpus"],
                       capture_output=True, text=True)
    p.write_text(orig)
    out = r.stdout + r.stderr
    if "error[" in out or "could not compile" in out:
        print(f"{name:34s} did not compile")
        continue
    hits = re.findall(r"^  ([a-z_]+::[a-z_0-9]+)", out, re.M)
    caught = len(hits)
    print(f"{name:34s} {caught:3d} record(s) notice" + ("   <-- NOTHING NOTICED" if caught == 0 else ""))
