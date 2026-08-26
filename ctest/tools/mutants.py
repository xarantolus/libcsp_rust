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
  ("hooks: crypto default refuses", "csp/src/hooks.rs",
   "    fn encrypt(&mut self, _data: &mut [u8], _len: usize) -> Option<usize> {\n        None",
   "    fn encrypt(&mut self, _data: &mut [u8], _len: usize) -> Option<usize> {\n        Some(_len)"),
  ("shutdown: frees connections", "csp/src/router.rs",
   "            let (closed, n) = self.conns.close_all(&mut drained);",
   "            let (closed, n) = (0usize, 0usize); let _ = &mut drained;"),
  ("shutdown: frees pending forwards", "csp/src/router.rs",
   "            drop(pool.from_index(packet));\n            // pop_pending counts a forward it is about to report; nothing is being",
   "            let _ = packet;\n            // pop_pending counts a forward it is about to report; nothing is being"),
  ("route: fan-out to every match", "csp/src/router.rs",
   "                Some(mut c) => {\n                    Self::set_dst(&mut c, h.dst);\n                    self.push_pending(h.iface, h.via, c.into_index());\n                }",
   "                Some(_c) => {}"),
  ("promisc: tap runs at all", "csp/src/router.rs",
   "        if self.promisc_enabled {", "        if false {"),
  ("promisc: tap sees forwarded", "csp/src/router.rs",
   "        if self.promisc_enabled {", "        if self.promisc_enabled && for_us {"),
  ("security: whole policy", "csp-core/src/security.rs",
   "    let mut body = payload;", "    let mut body = payload;\n    if true { return Ok(body); }"),
  # The CMP server. Every refusal below is a `goto discard` in the C: it answers nothing,
  # so a port that replies anyway tells a peer the request succeeded.
  ("cmp: reply type is flipped", "csp/src/service.rs",
   "kind: cmp::REPLY,", "kind: cmp::REQUEST,"),
  ("cmp: ident carries the hostname", "csp/src/service.rs",
   "                hostname: identity.hostname,", "                hostname: \"\","),
  ("cmp: ident keeps model and revision apart", "csp/src/service.rs",
   "                model: identity.model,\n                revision: identity.revision,",
   "                model: identity.revision,\n                revision: identity.model,"),
  ("cmp: unknown interface gets no if_stats", "csp/src/service.rs",
   "            None => Ok(None),\n        },",
   "            None => Ok(Some(IfStatsMsg { interface, stats: Default::default() }.encode(reply_header(cmp::code::IF_STATS), out)?)),\n        },"),
  ("cmp: a refused clock set is not reported as done", "csp/src/service.rs",
   "                if !hooks.set_clock(t.into()) {\n                    return Ok(None);\n                }",
   "                let _ = hooks.set_clock(t.into());"),
  ("cmp: a refused peek answers nothing", "csp/src/service.rs",
   "            if hooks.mem_read(addr, &mut buf[..n]).is_err() {\n                return Ok(None);\n            }",
   "            let _ = hooks.mem_read(addr, &mut buf[..n]);"),
  ("cmp: a refused poke answers nothing", "csp/src/service.rs",
   "            if hooks.mem_write(addr, data).is_err() {\n                return Ok(None);\n            }",
   "            let _ = hooks.mem_write(addr, data);"),
  ("cmp: a refused route_set answers nothing", "csp/src/service.rs",
   "            if !hooks.route_set(r.dest_node, r.netmask, r.interface, r.next_hop_via) {\n                return Ok(None);\n            }",
   "            let _ = hooks.route_set(r.dest_node, r.netmask, r.interface, r.next_hop_via);"),
  # Config -> Node -> IDENT. Node::new dropped these three outright, so the builder setter
  # had no effect on the only type that can route.
  ("node: keeps the configured hostname", "csp/src/node.rs",
   "            hostname: config.hostname,", "            hostname: \"\","),
  ("node: identity keeps model and revision apart", "csp/src/node.rs",
   "            model: self.model,\n            revision: self.revision,",
   "            model: self.revision,\n            revision: self.model,"),
  # csp_send_direct's destination policy, on both the forward path (Router::forward) and
  # the send path (Node::resolve) -- two separate implementations that must agree.
  # One policy now, so one set of mutations covers both the send and forward paths.
  ("policy: a routed broadcast is rewritten", "csp/src/route_policy.rs",
   "        if ifaces.is_broadcast_for(dst, idx) {\n            out_dst = version.max_node_id();\n        }",
   "        if false {\n            out_dst = version.max_node_id();\n        }"),
  ("policy: only a broadcast is rewritten", "csp/src/route_policy.rs",
   "        if ifaces.is_broadcast_for(dst, idx) {\n            out_dst = version.max_node_id();\n        }",
   "        {\n            out_dst = version.max_node_id();\n        }"),
  ("policy: the rewrite is sticky across the fan-out", "csp/src/route_policy.rs",
   "                dst: out_dst,", "                dst,"),
  ("policy: a local subnet is tried first", "csp/src/route_policy.rs",
   "        if !ifaces.is_within_subnet(dst, idx) {\n            continue;\n        }",
   "        if true {\n            continue;\n        }"),
  ("policy: a subnet match suppresses the table", "csp/src/route_policy.rs",
   "    if local_found {\n        return finish(n);\n    }", "    if false {\n        return finish(n);\n    }"),
  ("policy: split horizon is a subnet test", "csp/src/route_policy.rs",
   "        Some(e) => ifaces.is_within_subnet(e.addr, ingress),",
   "        Some(e) => { let _ = e; false },"),
  ("policy: split horizon applies at all", "csp/src/route_policy.rs",
   "    let vetoed = |idx: u8| ingress.is_some_and(|i| is_same_subnet(ifaces, idx, i));",
   "    let vetoed = |idx: u8| { let _ = idx; false };"),
  ("policy: the table is consulted", "csp/src/route_policy.rs",
   "        let matched = routes.find_all(dst, &mut found);", "        let matched = 0; let _ = routes;"),
  # RDP at the node. The state machine was fully implemented and the router never built an
  # rdp::Event, so a SYN reached a bound port and nothing came back.
  ("rdp: the router hands packets to the state machine", "csp/src/router.rs",
   "        if id.has_flag(csp_core::flags::RDP) {",
   "        if false && id.has_flag(csp_core::flags::RDP) {"),
  ("rdp: a control frame reaches the wire", "csp/src/router.rs",
   "            rdp::Action::SendControl(h) => {\n                drop(packet);\n                self.emit_rdp(pool, id, ifaces, h, &[], is_new, handle)\n            }",
   "            rdp::Action::SendControl(_h) => {\n                drop(packet);\n                Routed::Dropped(DropReason::RdpConsumed)\n            }"),
  ("rdp: the isn moves with the clock", "csp/src/router.rs",
   "            let iss = Self::initial_seq(now_ms);", "            let iss = 0u16;"),
  ("rdp: the reply carries our isn, not the peer's", "csp/src/router.rs",
   "            let iss = Self::initial_seq(now_ms);", "            let iss = header.seq_nr;"),
  ("rdp: an open connection emits nothing extra", "csp/src/router.rs",
   "            rdp::Action::Opened | rdp::Action::Nothing => {\n                drop(packet);\n                Routed::Dropped(DropReason::RdpConsumed)\n            }",
   "            rdp::Action::Opened | rdp::Action::Nothing => {\n                drop(packet);\n                let h = csp_core::rdp::Header { flags: csp_core::rdp::ACK, seq_nr: 0, ack_nr: 0 };\n                self.emit_rdp(pool, id, ifaces, h, &[], is_new, handle)\n            }"),
  ("rdp: the reply is addressed to the peer", "csp/src/router.rs",
   "            src: id.dst,\n            dst: id.src,", "            src: id.dst,\n            dst: id.dst,"),
  ("rdp: data reaches the application", "csp/src/router.rs",
   "            rdp::Action::Deliver => {\n                // Strip the trailer",
   "            rdp::Action::Deliver => {\n                if true { drop(packet); return Routed::Dropped(DropReason::RdpConsumed); }\n                // Strip the trailer"),
  ("rdp: the trailer is stripped before delivery", "csp/src/router.rs",
   "                packet.with_payload_mut(|_| (kept, ()));", "                let _ = kept;"),
  ("rdp: the node acknowledges data it delivers", "csp/src/router.rs",
   "        if let Some(ack) = self\n            .conns\n            .rdp_mut(handle)\n            .ok()\n            .and_then(|c| c.poll_ack(now_ms))\n        {",
   "        if let Some(ack) = None::<csp_core::rdp::Header> {"),
  ("rdp: the queued ack reaches the wire", "csp/src/router.rs",
   "            let _ = self.queue_rdp(pool, id, ifaces, ack, &[], false, handle);",
   "            let _ = ack;"),
  ("rdp: the handshake leaves no ack owing", "csp-core/src/rdp.rs",
   "                    self.rcv_lsa = h.seq_nr;\n                    self.state = State::SynRcvd;",
   "                    self.rcv_lsa = h.seq_nr.wrapping_sub(1);\n                    self.state = State::SynRcvd;"),
  ("rdp: the ack number advances", "csp-core/src/rdp.rs",
   "        Some(Header {\n            flags: ACK,\n            seq_nr: self.snd_nxt,\n            ack_nr: self.rcv_cur,",
   "        Some(Header {\n            flags: ACK,\n            seq_nr: self.snd_nxt,\n            ack_nr: self.rcv_irs,"),
  # Scratch arrays for draining a connection's receive queue. Every one of these APIs
  # refuses rather than partially draining -- a slot removed but not reported is a slot
  # nobody releases -- so an array shorter than one queue silently frees nothing.
  ("drain: the rst path sizes by RXQ", "csp/src/router.rs",
   "                let mut drained = [0u16; RXQ];\n                match self.conns.close(handle, &mut drained) {",
   "                let mut drained = [0u16; 8];\n                match self.conns.close(handle, &mut drained) {"),
  ("drain: the idle sweep sizes by RXQ", "csp/src/router.rs",
   "        let mut drained = [0u16; RXQ];\n        let (closed, n) = self\n",
   "        let mut drained = [0u16; 1];\n        let (closed, n) = self\n"),
  ("drain: shutdown sizes by RXQ", "csp/src/router.rs",
   "            let mut drained = [0u16; RXQ];\n            let (closed, n) = self.conns.close_all(&mut drained);",
   "            let mut drained = [0u16; 1];\n            let (closed, n) = self.conns.close_all(&mut drained);"),
  # The route-table text format -- the only way a route reaches a flying node from the
  # ground, and until now the one module with no external oracle at all.
  ("rtable: a short entry is skipped, not a full stop", "csp-core/src/rtable.rs",
   "        if entry.len() <= 1 {\n            continue;\n        }",
   "        if entry.len() <= 1 {\n            break;\n        }"),
  ("rtable: set clamps a wide netmask", "csp-core/src/rtable.rs",
   "        let netmask = if netmask > host_bits {\n            host_bits\n        } else {\n            netmask\n        };",
   "        let netmask = if netmask > host_bits {\n            return Err(Error::FieldOutOfRange { field: crate::Field::Destination });\n        } else {\n            netmask\n        };"),
  ("rtable: the next hop survives parsing", "csp-core/src/rtable.rs",
   "            Some(v) => Some(v.parse::<u16>().map_err(|_| bad(RouteError::BadVia))?),",
   "            Some(v) => { let _ = v; None },"),
  ("rtable: the netmask survives parsing", "csp-core/src/rtable.rs",
   "                Some(m.parse::<u16>().map_err(|_| bad(RouteError::BadNetmask))?),",
   "                None,"),
  ("rtable: a missing via means NO_VIA", "csp-core/src/rtable.rs",
   "            None => None,\n        };\n        if fields.next().is_some() {",
   "            None => Some(0),\n        };\n        if fields.next().is_some() {"),
  # SFP: the fragment MTU decides how a message is cut up, and the {SFP} x {RDP} cell is
  # the only place two stacked trailers have to agree about length.
  ("sfp: the mtu subtracts the rdp trailer", "csp-core/src/sfp.rs",
   "    if options & opts::RDP_REQ != 0 {\n        overhead += RDP_HEADER_LEN;\n    }",
   "    if false {\n        overhead += RDP_HEADER_LEN;\n    }"),
  ("sfp: the mtu subtracts its own trailer", "csp-core/src/sfp.rs",
   "    let mut overhead = HEADER_LEN;", "    let mut overhead = 0;"),
  ("sfp: the trailer is read from the end", "csp-core/src/sfp.rs",
   "        let split = data.len() - HEADER_LEN;\n        let (payload, trailer) = data.split_at(split);",
   "        let split = HEADER_LEN;\n        let (trailer, payload) = data.split_at(split);"),
  ("sfp: offset and total are not swapped", "csp-core/src/sfp.rs",
   "        let offset = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);\n        let total = u32::from_be_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);",
   "        let total = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);\n        let offset = u32::from_be_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);"),
  ("drain: unbind loops and sizes by RXQ", "csp/src/node.rs",
   "        let mut closed = 0usize;\n        loop {\n            let mut drained = [0u16; RXQ];",
   "        let mut closed = 0usize;\n        for _ in 0..1 {\n            let mut drained = [0u16; 32];"),
  ("drain: close sizes by RXQ", "csp/src/node.rs",
   "        let mut drained = [0u16; RXQ];\n        let n = self.router.conns.close(conn, &mut drained)?;",
   "        let mut drained = [0u16; 32];\n        let n = self.router.conns.close(conn, &mut drained)?;"),
  # Which broadcasts a node treats as its own. The C names the *ingress* interface, so a
  # broadcast for another subnet is relayed, not delivered -- and "widen it to every
  # interface" is the plausible wrong fix.
  ("broadcast: only the ingress interface's", "csp/src/router.rs",
   "            || ifaces.is_broadcast_for(id.dst, ingress)",
   "            || ifaces.indices().any(|i| ifaces.is_broadcast_for(id.dst, i))"),
  ("broadcast: is recognised at all", "csp/src/router.rs",
   "            || ifaces.is_broadcast_for(id.dst, ingress)", ""),
  ("broadcast: all-ones is always broadcast", "csp-core/src/id.rs",
   "        addr == self.max_node_id()\n    }", "        false\n    }"),
  ("broadcast: a delivered one is not relayed on", "csp/src/router.rs",
   "        if for_us {\n            return self.deliver_local(pool, packet, id, ifaces, now_ms);\n        }",
   "        if for_us && id.dst == self.address {\n            return self.deliver_local(pool, packet, id, ifaces, now_ms);\n        }"),
  ("service: an empty process list is not a reply", "csp/src/service.rs",
   "            if status.ps.is_empty() {\n                return Ok(None);\n            }",
   "            if false {\n                return Ok(None);\n            }"),
]

for name, path, old, new in MUTANTS:
    p = pathlib.Path(path)
    orig = p.read_text()
    if old not in orig:
        print(f"{name:34s} MUTATION DID NOT APPLY -- pattern gone")
        continue
    p.write_text(orig.replace(old, new, 1))
    # The whole csp suite, not just the corpus: a port-only invariant -- one libcsp has no
    # equivalent of, like `shutdown` -- can only be covered by a unit test, and counting
    # corpus records alone would report it as a hole.
    # --no-fail-fast: a broken unit test must not stop the corpus binary from running, or
    # every mutation that trips a unit test would report the corpus as blind to it.
    r = subprocess.run(["cargo","test","-p","csp","--all-features","--no-fail-fast"],
                       capture_output=True, text=True)
    p.write_text(orig)
    out = r.stdout + r.stderr
    if "error[" in out or "could not compile" in out:
        print(f"{name:34s} did not compile")
        continue
    # Corpus divergences are the two-space-indented "suite::case" lines the runner prints.
    records = len(re.findall(r"^  ([a-z_]+::[a-z_0-9]+)", out, re.M))
    # Any failing test, corpus or unit, opens a "---- <name> stdout ----" block. If the
    # corpus noticed, its block is one of them; otherwise every block is a unit test.
    blocks = len(re.findall(r"^---- (\S+) stdout ----", out, re.M))
    unit_only = blocks if records == 0 else 0

    if records:
        where = f"{records:3d} record(s)"
    elif unit_only:
        where = f"{unit_only:3d} unit test(s)"
    else:
        where = "  0"
    flag = "   <-- NOTHING NOTICED" if (records == 0 and unit_only == 0) else ""
    print(f"{name:34s} {where} notice{flag}")
