# libcsp Stress Testing

This repository includes a stress-test suite ported from `libcsp_rust`, supporting both Linux (SocketCAN) and STM32 (Embassy).

## Linux Stress Tests

### Setup
Ensure you have `vcan0` or a real CAN interface up:
```bash
sudo ip link add dev vcan0 type vcan
sudo ip link set vcan0 up
```

### Running
Open two terminals.

**Terminal 1 (Receiver):**
```bash
cargo run --example stress_rx -- vcan0
```

**Terminal 2 (Sender):**
```bash
cargo run --example stress_tx -- vcan0
```

The tests will automatically cycle through:
1. **Normal**: Connectionless / UDP-like transfers.
2. **RDP**: Reliable Datagram Protocol connections.
3. **SFP**: Simple Fragmentation Protocol for large blobs.
4. **RDP + SFP**: Reliable fragmented transfers.

---

## STM32 Stress Tests (Embassy)

The `embassy-example` is configured as a **Stress Receiver** by default.

### Flash and Run
```bash
cd embassy-example
cargo build --release
probe-rs run --chip STM32L4R5ZITx target/thumbv7em-none-eabihf/release/embassy-example
```

### Connectivity
Connect your STM32 CAN pins (PA11/PA12) to a CAN transceiver (e.g. SN65HVD230) and then to your Linux CAN interface.

**Run Linux Sender:**
```bash
cargo run --example stress_tx -- can0
```

The STM32 will verify incoming PRNG data and log statistics via RTT.

---

## Key Parameters

- **PRNG Seed**: `0x12345678` (Deterministic verification).
- **Data Port**: 10.
- **SFP Port**: 11.
- **MTU**: 200 bytes.
- **CAN Bitrate**: 1 Mbps (Adjust in `main.rs` and Linux `ip link`).
