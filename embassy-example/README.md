# Embassy Example - STM32L4R5 Stress Test Binaries

This directory contains Embassy-based firmware examples for the STM32L4R5 microcontroller, demonstrating CSP (Cubesat Space Protocol) stress testing in an embedded environment.

## Binaries

- **stress_rx** - CSP receiver stress test (RX side)
- **stress_tx** - CSP transmitter stress test (TX side)

## Building

### Prerequisites

- Rust with `thumbv7em-none-eabihf` target installed:
  ```bash
  rustup target add thumbv7em-none-eabihf
  ```
- ARM GNU Toolchain (for objcopy):
  ```bash
  sudo apt install gcc-arm-none-eabi  # Ubuntu/Debian
  ```

### Using Make

The provided Makefile automates building and extracting firmware binaries:

```bash
# Build everything and copy to top-level directory
make

# Just build the Rust binaries
make build

# Extract .bin files from ELF files
make binaries

# Copy files to top-level
make copy

# Clean build artifacts
make clean

# Show help
make help
```

### Manual Build

```bash
# Build both binaries
cargo build --release --target thumbv7em-none-eabihf

# Extract .bin file for flashing
arm-none-eabi-objcopy -O binary \
  target/thumbv7em-none-eabihf/release/stress_rx \
  stress_rx.bin
```

## Output Files

After running `make`, the following files will be created in the **embassy-example directory**:

- `stress_rx.elf` - RX binary with debug symbols (1.2 MB)
- `stress_rx.bin` - RX raw firmware binary for flashing (29 KB)
- `stress_tx.elf` - TX binary with debug symbols (1.1 MB)
- `stress_tx.bin` - TX raw firmware binary for flashing (27 KB)

## Flashing

Use `probe-rs` or your preferred STM32 flashing tool:

```bash
# Using probe-rs (recommended)
probe-rs run --chip STM32L4R5ZITx stress_rx.elf

# Or flash the .bin file directly at address 0x08000000
probe-rs download --chip STM32L4R5ZITx --format bin stress_rx.bin 0x08000000
```

## Target Hardware

- **MCU**: STM32L4R5ZITx (Cortex-M4F)
- **Architecture**: ARM Cortex-M4F with FPU (`thumbv7em-none-eabihf`)
- **Flash**: Starts at 0x08000000
- **RAM**: 640 KB

## Notes

- The binaries use Embassy async runtime for embedded Rust
- CSP is configured with `external-arch` feature, using Embassy primitives
- Debug symbols are included in .elf files (controlled by `[profile.release]` in Cargo.toml)
- LTO and size optimization are enabled for smaller binaries
