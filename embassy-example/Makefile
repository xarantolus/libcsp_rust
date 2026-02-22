# Makefile for building embassy-example binaries and extracting .bin files
#
# Builds stress_rx and stress_tx binaries for ARM Cortex-M4F (thumbv7em-none-eabihf)
# and extracts .bin files to the embassy-example directory.

# Configuration
TARGET := thumbv7em-none-eabihf
PROFILE := release
CARGO := cargo

# Binary names
BINARIES := stress_rx stress_tx

# Paths
TARGET_DIR := target/$(TARGET)/$(PROFILE)
OUTPUT_DIR := .

# Tools
OBJCOPY := arm-none-eabi-objcopy

# Output files
OUTPUT_ELF := $(foreach bin,$(BINARIES),$(OUTPUT_DIR)/$(bin).elf)
OUTPUT_BIN := $(foreach bin,$(BINARIES),$(OUTPUT_DIR)/$(bin).bin)

.PHONY: all build clean help

# Default target
all: build
	@echo "Building embassy-example binaries for $(TARGET)..."
	@$(MAKE) --no-print-directory extract-bins
	@$(MAKE) --no-print-directory copy-files
	@echo "✓ Build complete! Output files:"
	@ls -lh $(OUTPUT_ELF) $(OUTPUT_BIN)

# Build the Rust binaries
build:
	@echo "Compiling Rust binaries..."
	@$(CARGO) build --release --target $(TARGET) --bins

# Extract .bin files from ELF files
extract-bins:
	@for bin in $(BINARIES); do \
		echo "Extracting $$bin.bin..."; \
		$(OBJCOPY) -O binary $(TARGET_DIR)/$$bin $(TARGET_DIR)/$$bin.bin; \
	done

# Copy files to output directory
copy-files:
	@for bin in $(BINARIES); do \
		echo "Copying $$bin.elf and $$bin.bin..."; \
		cp $(TARGET_DIR)/$$bin $(OUTPUT_DIR)/$$bin.elf; \
		cp $(TARGET_DIR)/$$bin.bin $(OUTPUT_DIR)/$$bin.bin; \
	done

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@$(CARGO) clean
	@rm -f $(OUTPUT_ELF) $(OUTPUT_BIN)
	@echo "✓ Clean complete"

# Display help
help:
	@echo "Embassy Example Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build binaries, extract .bin files, and copy to output directory (default)"
	@echo "  build   - Build the Rust binaries only"
	@echo "  clean   - Remove build artifacts and output files"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Binaries: $(BINARIES)"
	@echo "Target: $(TARGET)"
	@echo "Profile: $(PROFILE)"
	@echo "Output directory: $(OUTPUT_DIR)"
	@echo ""
	@echo "Output files:"
	@echo "  $(OUTPUT_ELF)"
	@echo "  $(OUTPUT_BIN)"
