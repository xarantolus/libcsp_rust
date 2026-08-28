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

import json, pathlib, re, subprocess

MUTANTS = [
  ("cmp: request length gate", "csp-core/src/cmp.rs",
   "    if data.len() < request_len(h.code) {", "    if false {"),
  ("cmp: POKE carries its data", "csp-core/src/cmp.rs",
   "    if present != declared as usize {", "    if false {"),
  # Anchored on the line above it: `PeekV2` gained a `TAIL_LEN` of its own, and the bare
  # constant then matched two sites. The ambiguity guard caught it on the first run.
  ("cmp: peek tail zeroed", "csp-core/src/cmp.rs",
   "    /// **zeroes** the tail in every configuration.\n    pub const TAIL_LEN: usize = 3;",
   "    /// **zeroes** the tail in every configuration.\n    pub const TAIL_LEN: usize = 0;"),
  ("eth: zero-length segment", "csp-core/src/eth.rs",
   "        if h.seg_size == 0 {", "        if false {"),
  ("eth: running total bound", "csp-core/src/eth.rs",
   "        let end = offset + payload.len();\n        if end > self.total as usize {",
   "        let end = offset + payload.len();\n        if false {"),
  ("eth: segments append, not overwrite", "csp-core/src/eth.rs",
   "        let offset = self.received as usize;", "        let offset = 0;"),
  ("eth: the surplus past seg_size is ignored", "csp-core/src/eth.rs",
   "        let payload = &payload[..h.seg_size as usize];", "        let payload = payload;"),
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
  # The port's whole disagreement with the C on a truncated transfer. Making it agree has
  # to break the `diverges` record, or that record is decoration.
  ("sfp: truncation is not success", "csp/src/delivery.rs",
   "                None => return Err(Error::Truncated),",
   "                None => return Ok(None),"),
  ("sfp: cross-fragment total", "csp/src/delivery.rs",
   "            if frag.total != total {", "            if false {"),
  ("sfp: fragment order", "csp/src/delivery.rs",
   "            if frag.offset != expected {", "            if false {"),
  # A reply to a connection this node opened lands on an ephemeral port nothing bound.
  # Refusing it made `connect` useless, and every test passed anyway.
  ("conn: a connection is an endpoint too", "csp/src/router.rs",
   "        if !self.is_bound(id.dport) && existing.is_none() {",
   "        if !self.is_bound(id.dport) {"),
  # An unacknowledged packet must be resent, and the resent frame has to be one a real C
  # peer accepts -- only a peer notices a malformed retransmission.
  ("rdp: an unacknowledged packet is resent", "csp/src/router.rs",
   "                    TxAction::Retransmit { token, .. } => {",
   "                    TxAction::Retransmit { token, .. } => { let _ = token; continue; }\n                    #[allow(unreachable_patterns)]\n                    TxAction::Retransmit { token, .. } => {"),
  # An acknowledgement is a promise about a packet that was kept. Acking before the enqueue
  # is attempted promises one that was then dropped, and the peer discards its only copy.
  ("rdp: never acknowledge a dropped packet", "csp/src/router.rs",
   "                        pending_ack = false;\n                        self.counters.rx_queue_full += 1;",
   "                        self.counters.rx_queue_full += 1;"),
  # The C's receive-queue gate: stop acknowledging while the queue has less than a window of
  # spare room, so the peer stalls instead of overflowing a node that stopped reading.
  ("rdp: the receive-queue gate", "csp/src/router.rs",
   "        if RXQ > window && self.conns.rx_spare(handle).unwrap_or(0) < window {\n            pending_ack = false;\n        }",
   "        let _ = window;"),
  # If the port stops acknowledging, a C peer's send window shuts after `window_size` and
  # never reopens -- so its later messages simply never arrive. Only a peer that originates
  # more than one window of data can see it.
  ("rdp: we acknowledge what we receive", "csp-core/src/rdp.rs",
   "        if self.state != State::Open || !self.should_ack(now_ms) {\n            return None;\n        }",
   "        if true {\n            return None;\n        }"),
  # A reset connection and a full window are different refusals: one is permanent and the
  # other clears. Conflating them made an application retry for ever against a dead peer.
  # csp_close on an RDP connection sends ACK|RST and holds the slot until the peer answers.
  # Node::close released the slot and sent nothing: a C peer kept the connection open,
  # retransmitting into it, until its own timeout.
  ("rdp: close tells the peer and holds the slot", "csp/src/node.rs",
   "            .rdp_close(&self.storage.pool, &self.ifaces, conn, now_ms)?\n        {\n            return Ok(());\n        }",
   "            .rdp_close(&self.storage.pool, &self.ifaces, conn, now_ms)?\n        {\n            let _ = ();\n        }"),
  ("rdp: the close is an ACK|RST", "csp-core/src/rdp.rs",
   "                self.state = State::CloseWait;\n                self.last_activity = now_ms;\n                Action::SendControl(Header {\n                    flags: ACK | RST,",
   "                self.state = State::CloseWait;\n                self.last_activity = now_ms;\n                Action::SendControl(Header {\n                    flags: RST,"),
  ("rdp: a close the peer never answers times out", "csp-core/src/rdp.rs",
   "                if self.state == State::CloseWait {\n                    if now_ms.wrapping_sub(self.last_activity) > self.opts.conn_timeout {",
   "                if self.state == State::CloseWait {\n                    if false {"),
  ("rdp: a timed-out close releases what it held", "csp/src/router.rs",
   "        for h in timed_out.iter().take(n_timed_out).flatten() {",
   "        for h in timed_out.iter().take(0).flatten() {"),
  # csp_conn_is_active: an RDP connection that has heard nothing for conn_timeout, or is
  # closing, is not active -- this is what stops csp_sfp_send's loop on a dead peer.
  ("conn: an RDP connection goes inactive after conn_timeout", "csp/src/node.rs",
   "                if now_ms.wrapping_sub(r.last_activity) > r.opts.conn_timeout {\n                    return false;\n                }",
   ""),
  ("conn: a closing RDP connection is not active", "csp/src/node.rs",
   "                    csp_core::rdp::State::CloseWait | csp_core::rdp::State::Closed\n                ) {\n                    return false;\n                }",
   "                    csp_core::rdp::State::Closed\n                ) {\n                    return false;\n                }"),
  ("rdp: a reset is not back-pressure", "csp/src/node.rs",
   "            if !self.is_rdp_open(conn) {\n                return Err(Error::ConnectionReset);\n            }\n",
   ""),
  # The handshake's third leg. Without it a peer sits in SYN_RCVD and gives up -- and the
  # first data packet hides it, because that carries an ACK too.
  # Both of RDP's bare-ACK sites are the same five lines, so each runs on through the line
  # after it. Named for the handshake's third leg, this one had been mutating whichever came
  # first in the file -- see the `hits > 1` guard below.
  ("rdp: the initiator answers SYN|ACK", "csp-core/src/rdp.rs",
   "                    return Action::SendControl(Header {\n                        flags: ACK,\n                        seq_nr: self.snd_nxt,\n                        ack_nr: self.rcv_cur,\n                    });\n                }\n                Action::Nothing",
   "                    return Action::Opened;\n                }\n                Action::Nothing"),
  ("rdp: an out-of-window packet is re-acknowledged", "csp-core/src/rdp.rs",
   "                    return Action::SendControl(Header {\n                        flags: ACK,\n                        seq_nr: self.snd_nxt,\n                        ack_nr: self.rcv_cur,\n                    });\n                }\n                if h.has(ACK) {",
   "                    return Action::Nothing;\n                }\n                if h.has(ACK) {"),
  # The port could not send a fragment on a connection at all: `send` stamps the
  # connection's id over the caller's, and no connection option sets FRAG. A real C node
  # answered the resulting stream with CSP_ERR_SFP.
  ("sfp: a fragment leaves marked as one", "csp/src/node.rs",
   "        self.send_flagged(conn, packet, csp_core::flags::FRAG, now_ms)",
   "        self.send_flagged(conn, packet, 0, now_ms)"),
  # SFP appends its trailer in an 8-space closure and RDP in a 12-space one; without the
  # leading newline the shallower pattern is a substring of the deeper line as well.
  ("sfp: the trailer goes after the payload", "csp/src/node.rs",
   "\n            b[len..len + tn].copy_from_slice(&trailer[..tn]);",
   "\n            b[..tn].copy_from_slice(&trailer[..tn]);"),
  ("rdp: the trailer goes after the payload", "csp/src/node.rs",
   "\n                b[len..len + tn].copy_from_slice(&trailer[..tn]);",
   "\n                b[..tn].copy_from_slice(&trailer[..tn]);"),
  ("sfp: the trailer carries this fragment's offset", "csp/src/node.rs",
   "        let tn = csp_core::sfp::Fragment::encode(offset, total, &[], &mut trailer)?;",
   "        let tn = csp_core::sfp::Fragment::encode(0, total, &[], &mut trailer)?;"),
  ("rdp: connect proposes its option block", "csp/src/router.rs",
   "        self.queue_rdp_from_tick(pool, idout, ifaces, header, &body[..n])",
   "        self.queue_rdp_from_tick(pool, idout, ifaces, header, &[])"),
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
  # csp_promisc.c:59 -- "Yield to real traffic when the pool runs low". The port cloned down
  # to zero: the tap took the last buffers on the bus it was switched on to watch.
  # libcsp has no node address: everything a node originates leaves with source 0 and
  # `send_packet` fills it from the interface the packet leaves by (csp_io.c:119). The port
  # stamped one node-wide address, wrong on the second interface of a two-link node.
  ("source: a packet is sourced from the interface it leaves by", "csp/src/node.rs",
   "                if from_me && out_id.src == 0 {",
   "                if false {"),
  ("source: connect leaves the source to routing", "csp/src/node.rs",
   "            src: 0,\n            dst,\n            dport,\n            // A placeholder in range.",
   "            src: self.address,\n            dst,\n            dport,\n            // A placeholder in range."),
  ("source: an RDP control frame is sourced by its interface", "csp/src/router.rs",
   "                if reply.id().src == 0 {\n                    let mut id = reply.id();",
   "                if false {\n                    let mut id = reply.id();"),
  ("source: a retransmitted frame is sourced by its interface", "csp/src/router.rs",
   "                if idout.src == 0 {\n                    let mut id = idout;",
   "                if false {\n                    let mut id = idout;"),
  ("promisc: the tap yields to real traffic", "csp/src/router.rs",
   "            if pool.available() <= pool.capacity() / PROMISC_RESERVE_DIVISOR {\n                self.promisc_missed += 1;\n            } else if self.promisc_len < self.promisc.len() {",
   "            if self.promisc_len < self.promisc.len() {"),
  ("promisc: tap runs at all", "csp/src/router.rs",
   "        if self.promisc_enabled {", "        if false {"),
  ("promisc: tap sees forwarded", "csp/src/router.rs",
   "        if self.promisc_enabled {", "        if self.promisc_enabled && for_us {"),
  # A dropped packet must go back to the pool. Both no_path_through_the_node_leaks_a_buffer
  # tests measured only the C until now, so nothing watched the port's drop paths.
  ("router: a drop for an unbound port frees the packet", "csp/src/router.rs",
   "            return Routed::Dropped(DropReason::PortNotBound);",
   "            core::mem::forget(packet);\n            return Routed::Dropped(DropReason::PortNotBound);"),
  # Counting mutations per file found three with none at all and one with a single entry:
  # `crc32.rs` (0), `pool.rs` (0), `qfifo.rs` (0), `hmac.rs` (1). The two below are the
  # checks that decide whether a corrupted or unauthenticated packet reaches the
  # application, and nothing in 209 mutations had ever broken either.
  #
  # `pool.rs` stays at zero for now. The obvious mutation -- let `acquire` hand out a slot
  # whose refcount is not zero -- does not leave the program running and wrong: a test that
  # allocates until the pool is empty never gets `None`, and `just mutants` hangs instead of
  # reporting. That is the fourth mutation in this file to fail that way, and the rule is
  # written at the top of the happy-path block for a reason.
  ("crc32: a wrong checksum is refused", "csp-core/src/crc32.rs",
   "    if tail != expected {\n        return Err(crate::Error::BadChecksum);\n    }",
   "    if false {\n        return Err(crate::Error::BadChecksum);\n    }"),
  ("crc32: the checksum covers the payload", "csp-core/src/crc32.rs",
   "    c.update(payload);\n    let expected = c.finalize().to_be_bytes();",
   "    let expected = c.finalize().to_be_bytes();"),
  # csp_hmac_set_key stores SHA-1(material)[..16]. A node that stored the material itself
  # would MAC every packet with a different key from every C peer -- and fail all of them.
  ("hmac: the key is derived as csp_hmac_set_key derives it", "csp/src/node.rs",
   "        self.router.hmac_key = Some(csp_core::hmac::derive_key(material));",
   "        self.router.hmac_key = Some({\n            let mut k = [0u8; csp_core::hmac::KEY_LEN];\n            let n = material.len().min(k.len());\n            k[..n].copy_from_slice(&material[..n]);\n            k\n        });"),
  ("hmac: a wrong tag is refused", "csp-core/src/hmac.rs",
   "    if diff != 0 {\n        return Err(Error::BadChecksum);\n    }",
   "    if false {\n        return Err(Error::BadChecksum);\n    }"),
  # Three more from the unmovable list, each a *positive* rule that no "remove a guard"
  # mutation can reach: a plain packet is accepted, delivery does not depend on the tap, and
  # an unknown CMP code is not answered.
  ("security: a plain packet with no policy is accepted", "csp-core/src/security.rs",
   "    Ok(body)\n}", "    if endpoint_opts == 0 {\n        return Err(Refusal::Unsupported);\n    }\n    Ok(body)\n}"),
  # First written against `request_len`'s `_` arm, which only weakens a length gate the
  # dispatch below refuses anyway -- NOTHING NOTICED, correctly. The rule is in the dispatch.
  ("cmp: an unknown code is not answered", "csp-core/src/cmp.rs",
   "        other => Err(Error::LengthExceedsMaximum {\n            got: other as usize,\n            max: code::POKE_V2 as usize,\n        }),",
   "        _other => Ok(Query::Ident),"),
  # The mirror of `a finished transfer is reported finished`: a transfer that is *not*
  # finished must not be reported as one. `eth::an_incomplete_transfer_holds_a_buffer` is
  # the record that can see it, and nothing else could.
  ("eth: an unfinished transfer is not reported finished", "csp-core/src/eth.rs",
   "        self.key.is_some() && self.received >= self.total",
   "        self.key.is_some()"),
  # Four guards that had no mutation of their own, found by mining the "no mutation could
  # move this record" list. Three more were written beside them and deleted before commit:
  # they duplicated targets already covered further down this file, which the duplicate
  # check below now refuses. One of the three also crashed rather than diverged -- removing
  # the `payload.len() < seg_size` guard leaves the slice under it out of bounds, so it
  # panicked the corpus binary instead of failing a record.
  ("eth: segments must agree on the total", "csp-core/src/eth.rs",
   "                if h.packet_length != self.total {\n                    return Err(Error::InconsistentTotal {",
   "                if false {\n                    return Err(Error::InconsistentTotal {"),
  ("eth: a frame shorter than the header is refused", "csp-core/src/eth.rs",
   "    pub fn decode(data: &[u8]) -> Result<Header> {\n        if data.len() < HEADER_LEN {\n            return Err(Error::Truncated);\n        }",
   "    pub fn decode(data: &[u8]) -> Result<Header> {\n        if data.len() < HEADER_LEN {\n            return Err(Error::BufferTooSmall { needed: HEADER_LEN });\n        }"),
  ("dedup: off suppresses nothing", "csp/src/dedup.rs",
   "            DedupMode::Off => false,", "            DedupMode::Off => true,"),
  ("cmp: a reply is not a request", "csp-core/src/cmp.rs",
   "    if h.is_reply() {\n        return Err(Error::NotAReply { got: h.kind });\n    }",
   "    if false {\n        return Err(Error::NotAReply { got: h.kind });\n    }"),
  # **Happy-path mutations.** Nearly every mutation above weakens a guard, and weakening a
  # guard cannot move a record that never trips it -- which is why 27 records could not be
  # moved by anything and why five new guard mutations moved only two of them. These break
  # correct behaviour instead: the completion report, the payload offset, the ISN, the
  # duplicate answer, and the rule that a reply is not answered.
  ("eth: a finished transfer is reported finished", "csp-core/src/eth.rs",
   "        self.received = self.received.saturating_add(payload.len() as u16);\n        Ok(self.is_complete())",
   "        self.received = self.received.saturating_add(payload.len() as u16);\n        Ok(false)"),
  ("eth: a segment lands where it belongs", "csp-core/src/eth.rs",
   "        out[offset..end].copy_from_slice(payload);",
   "        out[..payload.len()].copy_from_slice(payload);"),
  ("dedup: a packet not seen before is not a duplicate", "csp/src/dedup.rs",
   "        self.next = (self.next + 1) % DEDUP_COUNT;\n        false",
   "        self.next = (self.next + 1) % DEDUP_COUNT;\n        true"),
  ("rdp: the ISN is a function of the clock", "csp/src/router.rs",
   "        let mixed = now_ms.wrapping_mul(2_654_435_761);\n        ((mixed >> 16) ^ mixed) as u16",
   "        let _ = now_ms;\n        0"),
  # Seven records that no mutation could move. The tool cannot tell "measuring something no
  # mutation touches" from "not measuring the port at all", so each of these targets one of
  # them directly: if the record notices, it measures the port and the gap was in this list;
  # if it does not, the record is vacuous and that is the finding.
  ("eth: the header fields are not transposed", "csp-core/src/eth.rs",
   "        out[16..18].copy_from_slice(&self.src_addr.to_be_bytes());\n        out[18..20].copy_from_slice(&self.seg_size.to_be_bytes());",
   "        out[16..18].copy_from_slice(&self.seg_size.to_be_bytes());\n        out[18..20].copy_from_slice(&self.src_addr.to_be_bytes());"),
  ("eth: the ethertype reaches the wire", "csp-core/src/eth.rs",
   "        out[12..14].copy_from_slice(&self.ethertype.to_be_bytes());",
   "        out[12..14].copy_from_slice(&0u16.to_be_bytes());"),
  ("dedup: the window is 100 ms", "csp/src/dedup.rs",
   "pub const DEDUP_WINDOW_MS: u32 = 100;", "pub const DEDUP_WINDOW_MS: u32 = 0;"),
  ("cmp: the peek maximum is 200", "csp-core/src/cmp.rs",
   "    pub const PEEK_MAX: usize = 200;", "    pub const PEEK_MAX: usize = 255;"),
  ("security: an unsupported flag is refused", "csp-core/src/security.rs",
   "    if id.has_flag(flags::HMAC) && !support.hmac {\n        return Err(Refusal::Unsupported);\n    }",
   "    if false {\n        return Err(Refusal::Unsupported);\n    }"),
  # `check_default` has two branches and nothing had ever driven either: an early return
  # when something is already default, and a sweep that marks everything else. What it
  # decides is whether an unroutable packet is dropped or put on every link.
  ("check_default: an existing default is left alone", "csp/src/iflist.rs",
   "        if self.find_default().is_some() {\n            return 0;\n        }", "        {}"),
  ("check_default: the sweep really marks", "csp/src/iflist.rs",
   "            if let Some(e) = self.get_mut(i) {\n                e.is_default = true;\n                n += 1;\n            }",
   "            if self.get_mut(i).is_some() {\n                n += 1;\n            }"),
  # The ARP table decides the destination MAC of every outgoing Ethernet frame. Neither
  # `csp_eth_arp_set_addr` nor `csp_eth_arp_get_addr` had ever been called by a harness, and
  # `ArpTable` had no caller anywhere.
  ("arp: an unknown address broadcasts", "csp-core/src/eth.rs",
   "        BROADCAST_MAC\n    }\n\n    /// Whether `addr` is known, without touching its recency.",
   "        [0u8; MAC_LEN]\n    }\n\n    /// Whether `addr` is known, without touching its recency."),
  ("arp: a moved peer is followed", "csp-core/src/eth.rs",
   "            e.1 = mac;\n            e.2 = now;\n            return;",
   "            e.2 = now;\n            return;"),
  ("arp: a full table still learns", "csp-core/src/eth.rs",
   "        self.entries[oldest] = Some((addr, mac, now));", "        let _ = oldest;"),
  # The v2 peek/poke reply must be CMP_PEEK_V2_SIZE(len) = 11 + 3 + len. Three bytes short
  # and `csp_transaction_persistent` refuses the whole reply, so ground cannot peek at all.
  ("cmp v2: the reply carries its tail", "csp-core/src/cmp.rs",
   "        let body = Self::HEADER_LEN + self.data.len();\n        let needed = if self.data.is_empty() {\n            Self::HEADER_LEN\n        } else {\n            body + Self::TAIL_LEN\n        };\n        if out.len() < needed {\n            return Err(Error::BufferTooSmall { needed });\n        }\n        out[0] = h.kind;\n        out[1] = h.code;\n        out[Header::LEN..Header::LEN + 8].copy_from_slice(&self.vaddr.to_be_bytes());",
   "        let body = Self::HEADER_LEN + self.data.len();\n        let needed = body;\n        if out.len() < needed {\n            return Err(Error::BufferTooSmall { needed });\n        }\n        out[0] = h.kind;\n        out[1] = h.code;\n        out[Header::LEN..Header::LEN + 8].copy_from_slice(&self.vaddr.to_be_bytes());"),
  ("cmp v2: the tail is zeroed", "csp-core/src/cmp.rs",
   "        out[body..needed].fill(0);", "        out[body..needed].fill(0xAA);"),
  # `csp_rtable_save` writes the text a ground tool reads back off a node: the netmask is
  # omitted for a host route, and entries join with a bare comma. Nothing had compared it --
  # `format_route` had no caller outside its own unit tests and there was no whole-table save.
  ("rtable save: a host route drops its mask", "csp-core/src/rtable.rs",
   "        if u32::from(route.netmask) != version.host_bits() {", "        if true {"),
  ("rtable save: a subnet route keeps its mask", "csp-core/src/rtable.rs",
   "        if u32::from(route.netmask) != version.host_bits() {", "        if false {"),
  ("rtable save: entries join with a comma", "csp-core/src/rtable.rs",
   "                out[n] = b',';", "                out[n] = b' ';"),
  # The idle sweep is for connections a *peer* opened and nobody accepted. Taking a client
  # connection as well drops the reply the application is waiting for; taking nothing leaves
  # the table exhaustible by one packet per slot. libcsp expires neither.
  ("idle sweep: not a connection we opened", "csp/src/conn.rs",
   "            if c.state != State::Open || c.kind != Kind::Server {",
   "            if c.state != State::Open {"),
  ("idle sweep: but it does sweep", "csp/src/conn.rs",
   "            if c.state != State::Open || c.kind != Kind::Server {",
   "            if true {"),
  # The ephemeral source port must be a function of the connection slot, as it is in the C
  # (`csp_conn.c:58`), because `find` matches a client connection on that port alone. It was
  # a rotating counter, which held only until it wrapped.
  ("sport: derived from the slot, not a counter", "csp/src/node.rs",
   "        EPHEMERAL_FIRST + (idx % span) as u8",
   "        let _ = idx;\n        EPHEMERAL_FIRST"),
  # `csp_send_prio` writes the priority into the *connection*; the port applies it to the
  # packet. A deliberate divergence (SCOPE.md 32) that nothing had ever measured -- the C
  # side of it was a doc comment.
  ("send_prio: the override reaches the wire", "csp/src/node.rs",
   "        let mut id = self.router.conns.id_out(conn)?;\n        id.pri = pri;",
   "        let mut id = self.router.conns.id_out(conn)?;\n        let _ = pri;"),
  # `CSP_SO_CONN_LESS`: the packet goes to the socket, not to a connection, so a server on
  # such a port takes peers it has no connections for. Nothing had ever named the option.
  ("conn_less: the socket is the endpoint", "csp/src/router.rs",
   "        if self.is_conn_less(id.dport) {", "        if false {"),
  # "an ordinary port is not connection-less" is deliberately NOT a mutation here. Making
  # every bound port connection-less takes down the corpus binary itself -- every
  # connection-oriented record loses its endpoint at once -- and the run reports REPLAY
  # PANICKED, which says nothing about coverage. The property is covered, and verified as a
  # control, by the ordinary-port half of `difftest/tests/node_conn_less.rs`.
  ("conn_less: recvfrom reads that queue", "csp/src/node.rs",
   "        Ok(self\n            .router\n            .take_conn_less()\n            .and_then(|idx| self.pool().from_index(idx)))",
   "        Ok(None)"),
  # The catch-all, `csp_bind(socket, CSP_ANY)`, which the port had no way to express at all.
  # Four rules: it delivers, the port ceiling still bounds it, releasing it stops delivery,
  # and releasing it hands the buffers back.
  # csp_socket_close leaves an accepted connection open; unbind closed it.
  ("unbind: an accepted connection survives", "csp/src/conn.rs",
   "                || c.idin.dport != port\n                || c.accepted\n            {",
   "                || c.idin.dport != port\n            {"),
  ("bind_any: the catch-all delivers an unbound port", "csp/src/router.rs",
   "        (port as usize) < PORTS && (self.bound[port as usize] || self.any_bound)",
   "        (port as usize) < PORTS && self.bound[port as usize]"),
  ("bind_any: PORTS still bounds the catch-all", "csp/src/router.rs",
   "        (port as usize) < PORTS && (self.bound[port as usize] || self.any_bound)",
   "        self.any_bound || ((port as usize) < PORTS && self.bound[port as usize])"),
  ("bind_any: releasing it stops delivery", "csp/src/router.rs",
   "    pub fn unbind_any(&mut self, drained: &mut [u16]) -> (usize, usize) {\n        self.any_bound = false;",
   "    pub fn unbind_any(&mut self, drained: &mut [u16]) -> (usize, usize) {"),
  ("bind_any: releasing it returns the buffers", "csp/src/router.rs",
   "            let (c, k) = self.conns.close_port(port as u8, &mut drained[n..]);\n            closed += c;\n            n += k;",
   "            let (c, _k) = self.conns.close_port(port as u8, &mut drained[n..]);\n            closed += c;"),
  # The KISS decoder's escape rule, against the C. The port's decoder had never been driven
  # against libcsp at all -- only its encoder, port-to-C.
  # Deliberate deviation: a FEND that closes a frame opens the next. Regressing it to the
  # C's NOT_STARTED loses the second of two frames sharing a delimiter.
  ("kiss: a closing FEND opens the next frame", "csp-core/src/kiss.rs",
   "                    self.expect_command = true;\n                    self.mode = Mode::InFrame;\n                    return if done",
   "                    self.expect_command = false;\n                    self.mode = Mode::Idle;\n                    return if done"),
  ("kiss: an unknown escape drops the byte", "csp-core/src/kiss.rs",
   "                    TFESC => FESC,", "                    TFESC => FESC,\n                    other => other,"),
  # `if-i2c` was a default-on feature gating zero lines, with its three C functions mapped
  # to the *generic* Interface methods. These three are the behaviour that is not generic.
  ("i2c: the bus address is seven bits", "csp-core/src/i2c.rs",
   "    (addr & ADDR_MASK) as u8", "    (addr & 0xFF) as u8"),
  ("i2c: a next hop wins over the destination", "csp-core/src/i2c.rs",
   "    let addr = if via != NO_VIA { via } else { dst };", "    let addr = dst;"),
  ("i2c: the receive guard is four bytes, not a header", "csp-core/src/i2c.rs",
   "pub const MIN_FRAME_LEN: usize = 4;", "pub const MIN_FRAME_LEN: usize = 6;"),
  # The tap's payload, not its count or its destination. node_promisc.rs compared only
  # those two until the bytes were added, and a tap that copied the wrong packet or
  # truncated it reports the same count and the same destination.
  ("promisc: the tap copies the whole payload", "csp/src/router.rs",
   "            } else if self.promisc_len < self.promisc.len() {\n                if let Some(copy) = packet.deep_copy() {",
   "            } else if self.promisc_len < self.promisc.len() {\n                if let Some(mut copy) = packet.deep_copy() {\n                    copy.with_payload_mut(|b| (b.len().saturating_sub(1), true));"),
  # Aliases decide whether a command for the node's second address is delivered or
  # forwarded back out. Nothing named one until node_alias.rs.
  ("iflist: an alias is one of our addresses", "csp/src/iflist.rs",
   "        self.aliases\n            .iter()\n            .flatten()\n            .find(|a| a.addr == addr)\n            .map(|a| a.iface)\n    }",
   "        let _ = &self.aliases;\n        None\n    }"),
  ("client: a u32 reply must be exactly four bytes", "csp/src/client.rs",
   "    if reply.len() != 4 {", "    if reply.len() < 4 {"),
  ("client: the ps request carries the C's sentinel", "csp/src/client.rs",
   "pub const PS_REQUEST: [u8; 1] = [0x55];",
   "pub const PS_REQUEST: [u8; 1] = [0x56];"),
  # The two magic words, against the C's own client. A round trip inside the port cannot
  # catch these: client and server both read service::REBOOT_MAGIC.
  ("client: the reboot word is the C's", "csp/src/service.rs",
   "pub const REBOOT_MAGIC: u32 = 0x8007_8007;",
   "pub const REBOOT_MAGIC: u32 = 0x8007_8008;"),
  ("client: the shutdown word is the C's", "csp/src/service.rs",
   "pub const SHUTDOWN_MAGIC: u32 = 0xD1E5_529A;",
   "pub const SHUTDOWN_MAGIC: u32 = 0xD1E5_529B;"),
  # csp_route.c:288 -- the endpoint is the connection when one exists. Checked against the
  # node-wide value alone, a bare reply to a CRC32 connection reached the application.
  ("security: a reply is held to its own connection's policy", "csp/src/router.rs",
   "        let policy = existing\n            .and_then(|h| self.conns.opts(h).ok())\n            .unwrap_or(self.endpoint_opts);",
   "        let policy = self.endpoint_opts;"),
  ("security: an accepted connection inherits the socket policy", "csp/src/router.rs",
   "                match self.conns.alloc(reply, self.endpoint_opts, now_ms) {",
   "                match self.conns.alloc(reply, 0, now_ms) {"),
  ("security: whole policy", "csp-core/src/security.rs",
   "    let mut body = payload;", "    let mut body = payload;\n    if true { return Ok(body); }"),
  # The CMP server. Every refusal below is a `goto discard` in the C: it answers nothing,
  # so a port that replies anyway tells a peer the request succeeded.
  # The reply path, not the encoder. Nothing put a CMP reply on a wire until
  # node_cmp_server.rs: the served-by-a-real-node record stops after `respond_cmp` and
  # compares the bytes in memory, so a reply addressed to the wrong port matched it.
  ("cmp: the reply goes back to the asking port", "csp/src/node.rs",
   "            dport: req.sport,\n            sport: req.dport,",
   "            dport: req.dport,\n            sport: req.sport,"),
  ("cmp: the ident reply is the size the c struct expects", "csp-core/src/cmp.rs",
   "    pub const LEN: usize =\n        Header::LEN + len::HOSTNAME + len::MODEL + len::REVISION + len::DATE + len::TIME;",
   "    pub const LEN: usize =\n        Header::LEN + len::HOSTNAME + len::MODEL + len::REVISION + len::DATE + len::TIME - 1;"),
  # The built-in services had no comparison against libcsp of any kind until
  # node_service.rs -- no suite, no record, no vector. Each of these four fails exactly one
  # of its tests and no other.
  # Ethernet reassembly handled one sender at a time until the two_senders_* records;
  # all twenty suite_eth cases were one transfer each.
  ("eth: the reassembly key separates two senders", "csp-core/src/eth.rs",
   "        ((self.packet_id as u32) << 16) | (self.src_addr as u32)",
   "        (self.packet_id as u32) << 16"),
  # cfp::Pbufs -- the port's counterpart of csp_if_can_pbuf.c -- had no user anywhere
  # outside cfp.rs until node_can.rs drove it.
  ("can: the pool keys a reassembler per sender", "csp-core/src/cfp.rs",
   "        if let Some(i) = self\n            .slots\n            .iter()\n            .position(|s| matches!(s, Some((k, _, _)) if *k == key))",
   "        if let Some(i) = self\n            .slots\n            .iter()\n            .position(|s| s.is_some())"),
  ("can: the sweep reclaims only what has gone quiet", "csp-core/src/cfp.rs",
   "                if now_ms.wrapping_sub(*last) > timeout_ms {",
   "                if true {"),
  # SCOPE.md deviation: the C wedges a sender whose transfer was truncated, because
  # csp_can_pbuf_cleanup only runs when a *new* buffer is allocated. The port restarts on
  # the repeated begin. This mutation regresses it to the C's behaviour.
  ("can: a repeated begin restarts the transfer", "csp-core/src/cfp.rs",
   "            self.id = Some(Id::decode(Version::V2, &header)?);\n            self.next_fc = 1;\n            self.len = 0;",
   "            if self.id.is_some() {\n                return Err(Error::NoTransferInProgress);\n            }\n            self.id = Some(Id::decode(Version::V2, &header)?);\n            self.next_fc = 1;\n            self.len = 0;"),
  # CFP v1: `V1Reassembler` had no caller outside its own module before node_can_v1.rs --
  # not even a golden vector. The first three fail the send direction, the last two the
  # receive direction, and neither pair touches the other.
  ("can v1: the begin frame declares the total length", "csp-core/src/cfp.rs",
   "            data[V1_HEADER_SIZE..V1_DATA_OFFSET].copy_from_slice(&(total as u16).to_be_bytes());",
   "            data[V1_HEADER_SIZE..V1_DATA_OFFSET].copy_from_slice(&0u16.to_be_bytes());"),
  ("can v1: remain counts the frames still to come", "csp-core/src/cfp.rs",
   "            let remain = (total + V1_DATA_OFFSET - 1) / CAN_FRAME_SIZE;",
   "            let remain = (total + V1_DATA_OFFSET - 1) / CAN_FRAME_SIZE + 1;"),
  ("can v1: the fragmenter names its source", "csp-core/src/cfp.rs",
   "                id: v1_id(self.src, self.dest, TYPE_BEGIN, remain as u32, self.ident),",
   "                id: v1_id(0, self.dest, TYPE_BEGIN, remain as u32, self.ident),"),
  ("can v1: the declared length is read after the header", "csp-core/src/cfp.rs",
   "            let declared =\n                u16::from_be_bytes([data[V1_HEADER_SIZE], data[V1_HEADER_SIZE + 1]]) as usize;",
   "            let declared = u16::from_be_bytes([data[0], data[1]]) as usize;"),
  ("can v1: continuations append, not overwrite", "csp-core/src/cfp.rs",
   "            out[self.received..self.received + n].copy_from_slice(&data[..n]);\n            self.received += n;",
   "            out[..n].copy_from_slice(&data[..n]);\n            self.received += n;"),
  # csp_if_can.c had never been compiled, here or in ctest, so every CFP comparison was of
  # the identifier's bit layout with shim.c expanding the header macros itself.
  ("can: the fragmenter names its sender", "csp-core/src/cfp.rs",
   "            | ((self.sender as u32 & V2_SENDER_MASK) << V2_SENDER_OFFSET)",
   "            | ((0u32 & V2_SENDER_MASK) << V2_SENDER_OFFSET)"),
  ("can: the first frame carries the source address", "csp-core/src/cfp.rs",
   "        let ext = ((self.id.src as u32 & V2_SRC_MASK) << V2_SRC_OFFSET)",
   "        let ext = ((0u32 & V2_SRC_MASK) << V2_SRC_OFFSET)"),
  ("can: the last frame is marked as the end", "csp-core/src/cfp.rs",
   "            if n == total {\n                id |= 1 << V2_END_OFFSET;\n            }",
   ""),
  ("can: the reassembler tracks the fragment counter", "csp-core/src/cfp.rs",
   "        self.next_fc = (self.next_fc + 1) & V2_FC_MASK;",
   ""),
  # The bridge named an interface and dropped the packet -- the forwarding bug again, in
  # a path the C had never even been compiled for. The first of these reproduces it.
  ("bridge: a forwarded frame is handed to the caller", "csp/src/router.rs",
   "        Bridged::Forward {\n            iface: out,\n            packet: packet.into_index(),\n        }",
   "        Bridged::Forward {\n            iface: out,\n            packet: u16::MAX,\n        }"),
  ("bridge: each side goes out the other", "csp/src/router.rs",
   "        let out = if iface == a {\n            b\n        } else if iface == b {\n            a",
   "        let out = if iface == a {\n            b\n        } else if iface == b {\n            b"),
  ("bridge: dedup is unconditional, not gated on the mode", "csp/src/router.rs",
   "        if packet.with_frame(|f| self.dedup.is_duplicate(f, now_ms)) {\n            self.counters.duplicates += 1;\n            return Bridged::Dropped(DropReason::Duplicate);\n        }",
   "        if self.dedup_mode != crate::dedup::DedupMode::Off\n            && packet.with_frame(|f| self.dedup.is_duplicate(f, now_ms))\n        {\n            self.counters.duplicates += 1;\n            return Bridged::Dropped(DropReason::Duplicate);\n        }"),
  ("service: a ping is echoed whole", "csp/src/service.rs",
   "            out[..request_payload.len()].copy_from_slice(request_payload);\n            Ok(Some(request_payload.len()))",
   "            out[..request_payload.len()].copy_from_slice(request_payload);\n            Ok(Some(request_payload.len().saturating_sub(1)))"),
  ("service: counter replies are big-endian", "csp/src/service.rs",
   "pub fn encode_u32_reply(value: u32, out: &mut [u8]) -> Result<usize> {",
   "pub fn encode_u32_reply(value: u32, out: &mut [u8]) -> Result<usize> {\n    let value = value.swap_bytes();"),
  ("service: the magic word gates the reboot", "csp/src/service.rs",
   "                    _ => Err(Error::BadChecksum),",
   "                    _ => Ok(Request::Reboot),"),
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
  # The other two ways to get CLOCK wrong, both invisible without a client that waits.
  # (The refusal is the entry immediately below; no third one here for it.)
  ("cmp: a zero tv_sec is a read, not a set", "csp-core/src/cmp.rs",
   "                set: if t.is_query() { None } else { Some(t) },",
   "                set: Some(t),"),
  ("cmp: a clock reply is seconds then nanoseconds", "csp-core/src/cmp.rs",
   "        out[Header::LEN..Header::LEN + 4].copy_from_slice(&self.tv_sec.to_be_bytes());\n        out[Header::LEN + 4..Self::LEN].copy_from_slice(&self.tv_nsec.to_be_bytes());",
   "        out[Header::LEN..Header::LEN + 4].copy_from_slice(&self.tv_nsec.to_be_bytes());\n        out[Header::LEN + 4..Self::LEN].copy_from_slice(&self.tv_sec.to_be_bytes());"),
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
  # The ROUTE_SET_V2 reply is the request echoed. libcsp's client reads its fields back out
  # of that echo, so a transposed pair or a blanked name is what ground would see.
  ("cmp: the route_set echo keeps dest and via apart", "csp-core/src/cmp.rs",
   "        out[o..o + 2].copy_from_slice(&self.dest_node.to_be_bytes());\n        out[o + 2..o + 4].copy_from_slice(&self.next_hop_via.to_be_bytes());",
   "        out[o..o + 2].copy_from_slice(&self.next_hop_via.to_be_bytes());\n        out[o + 2..o + 4].copy_from_slice(&self.dest_node.to_be_bytes());"),
  ("cmp: the route_set echo carries the interface name", "csp-core/src/cmp.rs",
   "        put_str(&mut out[o + 6..o + 6 + len::IFACE], self.interface);",
   "        put_str(&mut out[o + 6..o + 6 + len::IFACE], \"\");"),
  ("cmp: the 32-bit peek address is big-endian", "csp-core/src/cmp.rs",
   "        out[Header::LEN..Header::LEN + 4].copy_from_slice(&self.addr.to_be_bytes());",
   "        out[Header::LEN..Header::LEN + 4].copy_from_slice(&self.addr.to_le_bytes());"),
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
   "                let out = self.emit_rdp(pool, id, ifaces, h, &[], is_new && !refused, handle);",
   "                let _ = h;\n                let out = Routed::Dropped(DropReason::RdpConsumed);"),
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
  # Delivered and held packets are stripped by identical lines. This was named for the
  # delivered path and had been mutating the held one, which comes first in the file.
  ("rdp: the trailer is stripped before delivery", "csp/src/router.rs",
   "                packet.with_payload_mut(|_| (kept, ()));\n                match self.conns.enqueue_rx(handle, packet.into_index()) {",
   "                let _ = kept;\n                match self.conns.enqueue_rx(handle, packet.into_index()) {"),
  ("rdp: a held packet is stripped too", "csp/src/router.rs",
   "                packet.with_payload_mut(|_| (kept, ()));\n                let slot = packet.into_index();",
   "                let _ = kept;\n                let slot = packet.into_index();"),
  # Re-anchored: the receive-path acknowledgement moved inside `if pending_ack` and gained
  # four spaces of indent, so this pattern silently started matching `ack_after_read`
  # instead -- a different function, with a different test story. A mutation that drifts
  # onto its neighbour reports the neighbour's coverage as this one's.
  # `poll_ack` is consulted identically from `work` and from `tick`; each pattern runs on
  # through its own send call so the two cannot be confused for each other.
  ("rdp: the node acknowledges data it delivers", "csp/src/router.rs",
   "            if let Some(ack) = self\n                .conns\n                .rdp_mut(handle)\n                .ok()\n                .and_then(|c| c.poll_ack(now_ms))\n            {\n                let _ = self.queue_rdp(pool, id, ifaces, ack, &[], false, handle);",
   "            if let Some(ack) = None::<csp_core::rdp::Header> {\n                let _ = self.queue_rdp(pool, id, ifaces, ack, &[], false, handle);"),
  ("rdp: the ack timer fires from tick", "csp/src/router.rs",
   "            if let Some(ack) = self\n                .conns\n                .rdp_mut(handle)\n                .ok()\n                .and_then(|c| c.poll_ack(now_ms))\n            {\n                let _ = self.queue_rdp_from_tick(pool, idout, ifaces, ack, &[]);",
   "            if let Some(ack) = None::<csp_core::rdp::Header> {\n                let _ = self.queue_rdp_from_tick(pool, idout, ifaces, ack, &[]);"),
  # An acknowledgement is progress: it resets the give-up counter. Without it a connection
  # on a lossy-but-working link is torn down after N retransmissions across its whole life.
  ("rdp: an acknowledgement is progress", "csp-core/src/rdp.rs",
   "                self.retransmits = 0;\n                continue;",
   "                continue;"),
  # An acknowledgement owed on the ack *timer*. Without the tick driving it, a peer that
  # sent fewer packets than the delay count waits for its own retransmission instead.
  ("rdp: the tick sends a delayed acknowledgement", "csp/src/router.rs",
   "        self.sweep_delayed_acks(pool, ifaces, now_ms);",
   "        let _ = &ifaces;"),
  # The release valve: without it a connection that stalled the peer never restarts it.
  ("rdp: reading restarts a stalled peer", "csp/src/router.rs",
   "        if let Some(ack) = self\n            .conns\n            .rdp_mut(handle)\n            .ok()\n            .and_then(|c| c.poll_ack(now_ms))\n        {\n            let _ = self.queue_rdp_from_tick(pool, idout, ifaces, ack, &[]);",
   "        if let Some(ack) = None::<csp_core::rdp::Header> {\n            let _ = self.queue_rdp_from_tick(pool, idout, ifaces, ack, &[]);"),
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
  # Re-pointed 2026-08-26. This used to shrink the array in the `Action::Closed` arm, which
  # an in-sequence RST reached; a reset now answers `ACK|RST` and drains from `SendControl`
  # instead, so that arm only ever sees connections with nothing queued and the old mutation
  # went dead. The sweep is what noticed.
  ("drain: an answered reset releases what was queued", "csp/src/router.rs",
   "                if reset_established {\n                    while let Ok(Some(slot)) = self.conns.dequeue_rx(handle) {",
   "                if false {\n                    while let Ok(Some(slot)) = self.conns.dequeue_rx(handle) {"),
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
  # The tap's ownership rules: a leak on one side, a buffer handed out twice on the other.
  # Eight ck_asserts in the C and no record until now.
  ("promisc: read clears the slot it hands over", "csp/src/router.rs",
   "            if let Some(idx) = slot.take() {\n                self.promisc_len -= 1;",
   "            if let Some(idx) = *slot {\n                self.promisc_len -= 1;"),
  ("promisc: the tap keeps every packet, not the newest", "csp/src/router.rs",
   "                    for slot in self.promisc.iter_mut() {\n                        if slot.is_none() {",
   "                    for slot in self.promisc.iter_mut() {\n                        if true {"),
  ("promisc: read hands something back", "csp/src/router.rs",
   "        if self.promisc_len == 0 {\n            return None;\n        }",
   "        if true {\n            return None;\n        }"),
  ("rdp: an unanswered SYN|ACK is retransmitted", "csp-core/src/rdp.rs",
   "                if self.state == State::SynRcvd\n                    && now_ms.wrapping_sub(self.ack_timestamp) > self.opts.packet_timeout\n                {",
   "                if false {"),
  ("rdp: retransmission gives up eventually", "csp-core/src/rdp.rs",
   "                    if self.retransmits >= MAX_RETRANSMITS {", "                    if false {"),
  ("rdp: the repeat carries the original sequence", "csp-core/src/rdp.rs",
   "                        seq_nr: self.snd_iss,\n                        // `rcv_cur`, not `rcv_irs`.",
   "                        seq_nr: self.snd_iss.wrapping_add(1),\n                        // `rcv_cur`, not `rcv_irs`."),
  ("rdp: the repeat is a SYN|ACK", "csp-core/src/rdp.rs",
   "                    self.retransmits += 1;\n                    return Action::SendControl(Header {\n                        flags: SYN | ACK,",
   "                    self.retransmits += 1;\n                    return Action::SendControl(Header {\n                        flags: ACK,"),
  ("rdp: the timer's frames reach the caller", "csp/src/conn.rs",
   "                rdp::Action::SendControl(h) => {\n                    send(c.idout, h);",
   "                rdp::Action::SendControl(h) => {\n                    let _ = h;"),
  ("rdp: a peer's proposed window is clamped", "csp-core/src/rdp.rs",
   "    pub fn decode_clamped(data: &[u8], max_window: u32) -> Result<SynOptions> {",
   "    pub fn decode_clamped(data: &[u8], max_window: u32) -> Result<SynOptions> {\n        let max_window = u32::MAX;"),
  ("rtable: the parser refuses a wide netmask", "csp-core/src/rtable.rs",
   "        if netmask.is_some_and(|m| m > host_bits) {\n            return Err(bad(RouteError::BadNetmask));\n        }",
   "        if false {\n            return Err(bad(RouteError::BadNetmask));\n        }"),
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
  # Both drain loops open with the same three lines, so each pattern runs through its own
  # call to stay unambiguous -- see the `hits > 1` guard below for what happened when one
  # of them did not.
  ("drain: unbind loops and sizes by RXQ", "csp/src/node.rs",
   "        let mut closed = 0usize;\n        loop {\n            let mut drained = [0u16; RXQ];\n            let (c, n) = self.router.unbind(port, &mut drained);",
   "        let mut closed = 0usize;\n        for _ in 0..1 {\n            let mut drained = [0u16; 32];\n            let (c, n) = self.router.unbind(port, &mut drained);"),
  ("drain: unbind_any loops and sizes by RXQ", "csp/src/node.rs",
   "        let mut closed = 0usize;\n        loop {\n            let mut drained = [0u16; RXQ];\n            let (c, n) = self.router.unbind_any(&mut drained);",
   "        let mut closed = 0usize;\n        for _ in 0..1 {\n            let mut drained = [0u16; 32];\n            let (c, n) = self.router.unbind_any(&mut drained);"),
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
   "        if for_us {\n            return self.deliver_local(pool, packet, id, ifaces, ingress, now_ms);\n        }",
   "        if for_us && id.dst == self.address {\n            return self.deliver_local(pool, packet, id, ifaces, ingress, now_ms);\n        }"),
  # Per-interface counters. The C's router keeps them (csp_route.c:229, :244) and CMP
  # IF_STATS is how the ground reads them; `IfList::Entry::stats` was never written.
  ("ifstats: the router counts a received packet", "csp/src/router.rs",
   "            e.stats.rx += 1;\n            e.stats.rxbytes += bytes;",
   "            let _ = bytes; let _ = &e;"),
  ("ifstats: rxbytes is the payload length", "csp/src/router.rs",
   "        let bytes = packet.with_payload(<[u8]>::len) as u32;",
   "        let bytes = packet.with_payload(<[u8]>::len) as u32 + 6;"),
  ("ifstats: a suppressed duplicate counts as dropped", "csp/src/router.rs",
   "                if let Some(e) = ifaces.get_mut(ingress) {\n                    e.stats.drop += 1;\n                }",
   "                {}"),
  ("ifstats: an auth failure is charged to its link", "csp/src/router.rs",
   "                        if let Some(e) = ifaces.get_mut(ingress) {\n                            e.stats.autherr += 1;\n                        }",
   "                        {}"),
  ("ifstats: a receive error is charged to its link", "csp/src/router.rs",
   "                        if let Some(e) = ifaces.get_mut(ingress) {\n                            e.stats.rx_error += 1;\n                        }",
   "                        {}"),
  # The Ethernet receive path's refusals. Twelve `eth::` records existed that no mutation
  # could move -- not because they measure nothing, but because nothing was breaking the
  # guards they cover. A malformed frame is the one input a peer fully controls.
  # Both lines together. Dropping only the guard leaves the slice below out of range, so
  # the mutation crashed rather than misbehaving -- it modelled a panic, not a defect. What
  # a receiver would actually do wrong is take the bytes that did arrive and treat the
  # segment as complete, which is what `csp_eth_rx` refuses via `ETH_HDR + seg_size >
  # received_len`.
  ("eth: a frame shorter than its segment is refused", "csp-core/src/eth.rs",
   "        if payload.len() < h.seg_size as usize {\n            return Err(Error::InconsistentTotal {\n                expected: h.seg_size as u32,\n                got: payload.len() as u32,\n            });\n        }\n        let payload = &payload[..h.seg_size as usize];",
   "        let payload = &payload[..core::cmp::min(h.seg_size as usize, payload.len())];"),
  ("eth: a zero-length transfer is refused", "csp-core/src/eth.rs",
   "                if h.packet_length == 0 {\n                    return Err(Error::ZeroTotal);\n                }",
   "                if false {\n                    return Err(Error::ZeroTotal);\n                }"),
  ("eth: a foreign ethertype is refused", "csp-core/src/eth.rs",
   "        if !h.is_csp() {\n            return Err(Error::UnexpectedEtherType { got: h.ethertype });\n        }",
   "        if false {\n            return Err(Error::UnexpectedEtherType { got: h.ethertype });\n        }"),
  ("eth: a zero-length segment is refused", "csp-core/src/eth.rs",
   "        if h.seg_size == 0 {\n            return Err(Error::EmptyFragment);\n        }",
   "        if false {\n            return Err(Error::EmptyFragment);\n        }"),
  ("eth: a transfer larger than the buffer is refused up front", "csp-core/src/eth.rs",
   "                if h.packet_length as usize > out.len() {",
   "                if false && h.packet_length as usize > out.len() {"),
  # The dedup window. Its boundary and its behaviour at the 32-bit clock wrap are the two
  # things a record can pin here; before 2026-08-26 the C suite measured both and traced
  # neither, so the port's window was compared to nothing.
  ("dedup: the window is 100ms", "csp/src/dedup.rs",
   "pub const DEDUP_WINDOW_MS: u32 = 100;", "pub const DEDUP_WINDOW_MS: u32 = 50;"),
  ("dedup: entries age by wrapping subtraction", "csp/src/dedup.rs",
   "            if now_ms.wrapping_sub(self.stamps[i]) > DEDUP_WINDOW_MS {",
   "            if now_ms > self.stamps[i].wrapping_add(DEDUP_WINDOW_MS) {"),
  ("rdp: a refused SYN is not announced and not kept", "csp/src/router.rs",
   "                let refused = is_new && (h.flags & csp_core::rdp::RST) != 0;",
   "                let refused = false && is_new && (h.flags & csp_core::rdp::RST) != 0;"),
  ("rdp: the delay count is bound by the negotiated window", "csp-core/src/rdp.rs",
   "            ack_delay_count: clamp(w(5), 1, window_size),",
   "            ack_delay_count: clamp(w(5), 1, max_window),"),
  # Which bytes the wire MAC covers. A tag computed over the wrong span still verifies
  # against itself, so every self-test passes and every real peer rejects the packet --
  # libcsp's own expected bytes are the only thing that catches it.
  ("hmac: the header is inside the tag when asked for", "csp-core/src/hmac.rs",
   "    if coverage == Coverage::HeaderAndPayload {\n        inner.update(header);\n    }\n    inner.update(payload);",
   "    inner.update(payload);"),
  ("rdp: delayed_acks is a flag, not a count", "csp-core/src/rdp.rs",
   "            delayed_acks: w(3) != 0,", "            delayed_acks: w(3) == 1,"),
  ("rdp: a proposed ack_timeout is adopted", "csp-core/src/rdp.rs",
   "            ack_timeout: clamp(w(4), MIN_ACK_TIMEOUT, conn_timeout),",
   "            ack_timeout: 250,"),
  ("rdp: an unfinished handshake times out", "csp-core/src/rdp.rs",
   "                if matches!(self.state, State::SynSent | State::SynRcvd)\n                    && now_ms.wrapping_sub(self.last_activity) > self.opts.conn_timeout\n                {",
   "                if false {"),
  # csp_rdp_set_opt: the options a node proposes are configurable. Mapped to a codec
  # function before, which passed the name check and configured nothing.
  ("rdp: connect proposes the configured options", "csp/src/router.rs",
   "        let proposed = self.rdp_options;",
   "        let proposed = csp_core::rdp::SynOptions::default();"),
  # csp_rdp.c:431 -- giving up goes through csp_conn_close, whose ACK|RST is the only thing
  # that tells the peer. Measured: the C sends exactly one reset when it gives up.
  ("rdp: giving up tells the peer", "csp/src/router.rs",
   "                        if let Ok(Some((idout, hdr))) =\n                            self.conns.rdp_close(handle, now_ms, RDP_MAX_WINDOW)\n                        {\n                            let _ = self.queue_rdp_from_tick(pool, idout, ifaces, hdr, &[]);\n                        }",
   "                        let _ = self.conns.rdp_close(handle, now_ms, RDP_MAX_WINDOW);"),
  # csp_rdp.c:443 -- an RDP_OPEN connection silent for conn_timeout is closed with ACK|RST.
  ("rdp: a silent established connection times out", "csp-core/src/rdp.rs",
   "                if self.state == State::Open\n                    && now_ms.wrapping_sub(self.last_activity) > self.opts.conn_timeout\n                {",
   "                if false {"),
  # The blind-reset defence. One injected frame with the right addresses and ports must
  # not be able to drop a link when the sequence number is wrong.
  ("rdp: a reset is honoured only in sequence", "csp-core/src/rdp.rs",
   "                _ if h.seq_nr == self.rcv_cur.wrapping_add(1) => {",
   "                _ if true => {"),
  ("rdp: a reset is answered", "csp-core/src/rdp.rs",
   "                    self.state = State::CloseWait;\n                    return Action::SendControl(Header {\n                        flags: ACK | RST,",
   "                    self.state = State::CloseWait;\n                    return Action::SendControl(Header {\n                        flags: ACK,"),
  ("rdp: an extended acknowledgement carries no data", "csp-core/src/rdp.rs",
   "                if h.has(EAK) {\n                    if h.has(ACK) {",
   "                if false {\n                    if h.has(ACK) {"),
  # The receive reorder queue, wired in 2026-08-26 after existing unused for the whole port.
  ("rdp: a packet ahead of the gap is held", "csp-core/src/rdp.rs",
   "                    if seq_between(h.seq_nr, expected, expected.wrapping_add(max_window as u16)) {",
   "                    if false {"),
  ("rdp: the gap-filler releases what was held", "csp/src/router.rs",
   "                        self.release_held(handle);", "                        {}"),
  ("conn: the receive and transmit queues share one budget", "csp/src/conn.rs",
   "        if c.rx_len + c.rx_reorder.len() + c.tx_unacked.len() >= RXQ {\n            return Err(Error::BufferTooSmall { needed: RXQ + 1 });\n        }\n        c.rx_reorder.insert(seq_nr, slot)",
   "        c.rx_reorder.insert(seq_nr, slot)"),
  # The RDP send path, built 2026-08-26 after existing nowhere at all.
  ("rdp: an outgoing data packet carries a trailer", "csp/src/node.rs",
   "            let appended = packet.with_payload_mut(|b| {",
   "            let appended = true || packet.with_payload_mut(|b| {"),
  ("rdp: a sent packet is held for retransmission", "csp/src/node.rs",
   "            if let Some(copy) = packet.deep_copy() {",
   "            if let Some(copy) = packet.deep_copy().filter(|_| false) {"),
  ("rdp: the window bounds what may be sent", "csp-core/src/rdp.rs",
   "        if seq_before(last, self.snd_nxt) {", "        if false {"),
  # The real bug this caught: `with_payload_mut`'s closure *sets* the length, and its slice
  # is the whole slot. Returning `b.len()` stretches every retransmission to the full buffer.
  ("rdp: a retransmission keeps its own length", "csp/src/router.rs",
   "                                (len, ())\n                            });",
   "                                (b.len(), ())\n                            });"),
  ("rdp: an acknowledgement releases what it covers", "csp/src/router.rs",
   "                    TxAction::Release { token } => drop(pool.from_index(token)),",
   "                    TxAction::Release { token } => { let _ = token; }"),
  ("rdp: snd_una advances on the peer's ack", "csp-core/src/rdp.rs",
   "                if h.has(ACK) {\n                    self.snd_una = h.ack_nr.wrapping_add(1);\n                    self.retransmits = 0;\n                }",
   "                if h.has(ACK) {\n                    self.retransmits = 0;\n                }"),
  ("rdp: consecutive sends take consecutive sequences", "csp-core/src/rdp.rs",
   "        self.snd_nxt = self.snd_nxt.wrapping_add(1);\n        Some(h)",
   "        Some(h)"),
  ("rdp: the send window admits exactly window_size", "csp-core/src/rdp.rs",
   "            .wrapping_add(self.opts.window_size as u16)\n            .wrapping_sub(1);",
   "            .wrapping_add(self.opts.window_size as u16)\n            .wrapping_sub(2);"),
  # The connection table's reuse paths. Both records existed and both were in the
  # "no mutation could move" list -- not because they measure nothing, but because nothing
  # here had ever broken connection lookup or release. They fail as soon as something does.
  # The promiscuous tap. Its three records sat in the "no mutation could move" list purely
  # because nothing had ever switched the tap off.
  ("promisc: the tap captures at all", "csp/src/router.rs",
   "        if self.promisc_enabled {\n            if pool.available() <= pool.capacity() / PROMISC_RESERVE_DIVISOR {",
   "        if false {\n            if pool.available() <= pool.capacity() / PROMISC_RESERVE_DIVISOR {"),
  ("promisc: the tap runs before the security check", "csp/src/router.rs",
   "        if self.promisc_enabled {\n            if pool.available() <= pool.capacity() / PROMISC_RESERVE_DIVISOR {",
   "        if self.promisc_enabled && self.endpoint_opts == 0 {\n            if pool.available() <= pool.capacity() / PROMISC_RESERVE_DIVISOR {"),
  ("conn: a second packet finds the open connection", "csp/src/conn.rs",
   "    pub fn find(&self, id: &Id) -> Option<Handle> {\n        for (i, c) in self.conns.iter().enumerate() {",
   "    pub fn find(&self, id: &Id) -> Option<Handle> {\n        return None;\n        #[allow(unreachable_code)]\n        for (i, c) in self.conns.iter().enumerate() {"),
  ("conn: close releases the slot", "csp/src/conn.rs",
   "        c.reset();\n        Ok(n)\n    }", "        let _ = &c;\n        Ok(n)\n    }"),
  # What libcsp's own service clients demand of a reply: the echo byte for byte, and four
  # big-endian bytes for the csp_get_* family. Each failure reads on the ground as a node
  # that did not answer, so none of them is visible without a real client.
  #
  # No byte-order entry here: `counter replies are big-endian` above already swaps them, by
  # a different anchor. The duplicate guard keys on (file, target, replacement) and cannot
  # see that two different edits have the same effect -- this one was caught by reading the
  # run's output, not by the tool.
  ("service: the u32 reply is four bytes", "csp/src/service.rs",
   "    out[..4].copy_from_slice(&value.to_be_bytes());\n    Ok(4)",
   "    out[..4].copy_from_slice(&value.to_be_bytes());\n    Ok(3)"),
  ("service: a ping is echoed verbatim", "csp/src/service.rs",
   "            out[..request_payload.len()].copy_from_slice(request_payload);",
   "            out[..request_payload.len()].fill(0);"),
  # The trailers `csp_send_direct_iface` appends to everything this node originates
  # (csp_io.c:247-271). Setting the flag without the bytes is what made every CMP reply
  # undeliverable to a stock libcsp ground station; each call site is covered separately.
  ("egress: an originated packet carries the trailer it promises", "csp/src/node.rs",
   "                if from_me\n                    && crate::egress::protect(\n                        &mut packet,",
   "                if false\n                    && crate::egress::protect(\n                        &mut packet,"),
  # Both RDP queue points carry the same three lines, so each is anchored on the line that
  # follows it -- `queue_rdp_from_tick` reads the destination next, `queue_rdp` comments.
  ("egress: an rdp timer's frame carries it too", "csp/src/router.rs",
   "        if crate::egress::protect(\n            &mut reply,\n            out_flags,\n            self.hmac_key.as_ref().map(|k| &k[..]),\n        )\n        .is_err()\n        {\n            self.counters.malformed += 1;\n            return Err(Routed::Dropped(DropReason::Malformed));\n        }\n        let dst = reply.id().dst;",
   "        if false {\n            self.counters.malformed += 1;\n            return Err(Routed::Dropped(DropReason::Malformed));\n        }\n        let dst = reply.id().dst;"),
  ("egress: an rdp reply carries it too", "csp/src/router.rs",
   "        if crate::egress::protect(\n            &mut reply,\n            out_flags,\n            self.hmac_key.as_ref().map(|k| &k[..]),\n        )\n        .is_err()\n        {\n            self.counters.malformed += 1;\n            return Err(Routed::Dropped(DropReason::Malformed));\n        }\n\n        // Route it the way any outgoing packet is routed",
   "        if false {\n            self.counters.malformed += 1;\n            return Err(Routed::Dropped(DropReason::Malformed));\n        }\n\n        // Route it the way any outgoing packet is routed"),
  # The three ways to get csp_conn.c:112 wrong. A client connection matches on dport
  # alone, so answers to a broadcast reach it whoever sent them; a server one also
  # matches the source, so two peers are two connections. Tighten the first, loosen
  # either, and one of the two conn records stops reproducing the C.
  ("conn: a client connection ignores who answered", "csp/src/conn.rs",
   "                Kind::Client => c.idin.dport == id.dport,",
   "                Kind::Client => c.idin.dport == id.dport && c.idin.src == id.src,"),
  ("conn: a client connection still checks the port", "csp/src/conn.rs",
   "                Kind::Client => c.idin.dport == id.dport,",
   "                Kind::Client => true,"),
  # The port as RDP *responder*: a SYN|ACK that is only a SYN. libcsp's SYN_SENT arm
  # refuses it and csp_connect returns NULL, which node_rdp_responder.rs asserts.
  ("rdp: the answer to a syn acknowledges it", "csp-core/src/rdp.rs",
   "                    return Action::SendControl(Header {\n                        flags: SYN | ACK,\n                        seq_nr: self.snd_iss,\n                        ack_nr: self.rcv_irs,",
   "                    return Action::SendControl(Header {\n                        flags: SYN,\n                        seq_nr: self.snd_iss,\n                        ack_nr: self.rcv_irs,"),
  ("conn: a server connection is per peer", "csp/src/conn.rs",
   "                    c.idin.dport == id.dport && c.idin.sport == id.sport && c.idin.src == id.src",
   "                    c.idin.dport == id.dport && c.idin.sport == id.sport"),
  ("id: the fragment flag is read", "csp-core/src/id.rs",
   "    pub const fn is_fragment(&self) -> bool {\n        self.has_flag(crate::flags::FRAG)",
   "    pub const fn is_fragment(&self) -> bool {\n        false && self.has_flag(crate::flags::FRAG)"),
  ("service: an empty process list is not a reply", "csp/src/service.rs",
   "            if status.ps.is_empty() {\n                return Ok(None);\n            }",
   "            if false {\n                return Ok(None);\n            }"),
]

# Every corpus record that some mutation made fail. A record that never appears here is
# one no mutation in this suite can move -- either it is measuring something nothing
# touches, or it is not measuring the port at all. `replay_node_send` reported
# `"buffers_lost": 0` as a literal for months, so its two records were in the second
# category and looked exactly like the first.
fired = set()

# No two mutations may share a name, or a (file, target, replacement) triple. A duplicate is
# dead weight: it inflates the count, prints the same line twice, and -- the reason this
# exists -- makes a reader think coverage grew when the same guard was simply named again.
# Five of seven mutations added in one sitting duplicated patterns already in this file, and
# the ambiguity guard could not see it: that one compares a pattern against the *source*,
# not against the other patterns.
#
# Sharing a target with a *different* replacement is deliberate and common -- `bind_any`
# breaks one condition two ways, and so does `rtable save` -- so the triple is the key, not
# the target alone.
_names, _edits = {}, {}
for _n, _p, _o, _new in MUTANTS:
    if _n in _names:
        raise SystemExit(f"two mutations are named {_n!r}")
    _names[_n] = True
    if (_p, _o, _new) in _edits:
        raise SystemExit(f"{_n!r} makes the same edit as {_edits[(_p, _o, _new)]!r}")
    _edits[(_p, _o, _new)] = _n

for name, path, old, new in MUTANTS:
    p = pathlib.Path(path)
    orig = p.read_text()
    hits = orig.count(old)
    if hits == 0:
        print(f"{name:34s} MUTATION DID NOT APPLY -- pattern gone")
        continue
    # A pattern matching twice silently mutates whichever comes first in the file, which is
    # not necessarily the one the mutation is named after. `drain: unbind loops and sizes by
    # RXQ` moved from `Node::unbind` to a `Node::unbind_any` written later with the same
    # three opening lines, and reported NOTHING NOTICED -- the mutation had gone somewhere
    # nobody was testing, which reads identically to a hole in the tests.
    if hits > 1:
        print(f"{name:34s} MUTATION IS AMBIGUOUS -- pattern matches {hits} sites")
        continue
    p.write_text(orig.replace(old, new, 1))
    # The whole csp suite, not just the corpus: a port-only invariant -- one libcsp has no
    # equivalent of, like `shutdown` -- can only be covered by a unit test, and counting
    # corpus records alone would report it as a hole.
    # --no-fail-fast: a broken unit test must not stop the corpus binary from running, or
    # every mutation that trips a unit test would report the corpus as blind to it.
    # `-p csp-core` as well as `-p csp`: most mutations target `csp-core/src`, and the unit
    # tests that cover them live in that crate. Running only `csp` made the unit-test leg
    # blind there, so four Ethernet guards with unit tests asserting the exact error they
    # raise were reported as holes nothing noticed.
    # `difftest` is the only thing covering the port against a *running* C node, so a
    # mutation guarded only there would otherwise score as a hole nothing noticed -- the RDP
    # handshake's third leg was exactly that case. But it links the C library into seven test
    # binaries, and running it for all 127 mutations took the sweep past fifty minutes, which
    # is long enough that it stops being run at all.
    #
    # So: cheap packages first, and pay for `difftest` only when nothing cheap noticed. The
    # guarantee is unchanged -- no mutation is ever reported unnoticed without difftest
    # having been tried -- and the expensive leg runs for a handful of mutations instead of
    # every one.
    def run(pkgs):
        return subprocess.run(["cargo","test",*[a for pk in pkgs for a in ("-p",pk)],
                               "--all-features","--no-fail-fast"],
                              capture_output=True, text=True)

    r = run(["csp","csp-core"])
    out = r.stdout + r.stderr
    if "error[" not in out and "could not compile" not in out and "FAILED" not in out:
        r = run(["csp","csp-core","difftest"])
        out = r.stdout + r.stderr
    p.write_text(orig)
    if "error[" in out or "could not compile" in out:
        print(f"{name:34s} did not compile")
        continue
    # Corpus divergences are the two-space-indented "suite::case" lines the runner prints.
    named = re.findall(r"^  ([a-z_]+::[a-z_0-9]+)", out, re.M)
    fired.update(named)
    records = len(named)
    # Any failing test, corpus or unit, opens a "---- <name> stdout ----" block. If the
    # corpus noticed, its block is one of them; otherwise every block is a unit test.
    names = re.findall(r"^---- (\S+) stdout ----", out, re.M)
    blocks = len(names)
    unit_only = blocks if records == 0 else 0

    # A replay that panics is not a replay that measured something. The run is red either
    # way, but the failure names no record and this counter sees nothing -- so the mutation
    # scores as "some unit test noticed", and the records that actually cover the code sit
    # in the never-moved list looking vacuous. That masked every promiscuous-tap mutation,
    # and then every RDP control-frame mutation. Call it out by name instead of counting it.
    HARNESS = {"the_port_reproduces_what_the_c_did", "every_record_has_a_replay"}
    panicked = [n for n in names if n in HARNESS] if records == 0 else []
    if panicked:
        print(f"{name:34s} REPLAY PANICKED -- {panicked[0]} reported no record")
        continue

    if records:
        where = f"{records:3d} record(s)"
    elif unit_only:
        where = f"{unit_only:3d} unit test(s)"
    else:
        where = "  0"
    flag = "   <-- NOTHING NOTICED" if (records == 0 and unit_only == 0) else ""
    print(f"{name:34s} {where} notice{flag}")

# --- which records no mutation could move -------------------------------------------
corpus = pathlib.Path(__file__).resolve().parents[2] / "corpus" / "ctest.jsonl"
all_records = set()
for line in corpus.read_text().splitlines():
    if not line.strip():
        continue
    r = json.loads(line)
    all_records.add(f"{r['suite']}::{r['case']}")

never = sorted(all_records - fired)
print()
print(f"records moved by some mutation: {len(fired)}/{len(all_records)}")
if never:
    print("records no mutation could move -- each is either measuring something no")
    print("mutation touches, or not measuring the port at all:")
    for n in never:
        print(f"    {n}")
