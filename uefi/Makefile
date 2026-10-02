# Makefile for the MFTAH CLI.
# 
# Copyright (C) 2024-2026 Zack Puhl <github@xmit.xyz>
# 
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, version 3.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along with
# this program. If not, see https://www.gnu.org/licenses/.
#
#

ifneq ($(V),1)
.SILENT:
endif

SUPPARCHS		= x86_64 # aarch64 riscv64 loongarch64 ia64 mips64el

# Must be set to one of the members from SUPPARCHS.
ARCH			:= x86_64

ifeq ($(filter $(ARCH),$(SUPPARCHS)),)
$(error '$(ARCH)' is not a supported architecture)
endif


CC				= clang

MFTAH_DIR		= ../protocol
GNUEFI_DIR		= gnu-efi
SRC_DIR			= src
BUILD_DIR		= build
OBJ_DIR			= $(BUILD_DIR)/obj

EFIINC_DIR		= $(GNUEFI_DIR)/inc
EFIINCS			= -Iinclude -I$(MFTAH_DIR)/include \
					-I$(EFIINC_DIR) -I$(EFIINC_DIR)/$(ARCH) -I$(EFIINC_DIR)/protocol

EFILIB			= $(GNUEFI_DIR)/$(ARCH)
EFILIBS			= -L$(EFILIB)/lib -L$(EFILIB)/gnuefi

LIBGNUEFI		= $(EFILIB)/gnuefi/libgnuefi.a
LIBEFI			= $(EFILIB)/lib/libefi.a

MFTAHLIBS		= -L$(MFTAH_DIR)/build
LIBMFTAH		= $(MFTAH_DIR)/build/libmftah.a

OPTIM			= -O3
CFLAGS			= -target $(ARCH)-unknown-windows \
					-ffreestanding \
					-DMFTAH_ARCH=$(ARCH) \
					-masm=intel -mno-stack-arg-probe \
					-Wall \
					$(EFIINCS) $(OPTIM) \
					-DMFTAH_RELEASE_DATE=$(shell printf "0x`date +%Y``date +%m`%d" `date +%02d`)
LDFLAGS			= -target $(ARCH)-unknown-windows \
					-nostdlib \
					-Wl,-entry:efi_main \
					-Wl,-subsystem:efi_application \
					-fuse-ld=lld-link \
					-mno-stack-arg-probe \
					$(EFILIBS) \
					$(MFTAHLIBS)

SRCS_GNU_EFI	= $(shell find $(GNUEFI_DIR)/lib -maxdepth 1 -type f -name "*.c" | grep -Pvi '(entry|lock)\.')
SRCS_ARCH		= $(shell find $(GNUEFI_DIR)/lib/$(ARCH) -maxdepth 1 -type f -name "*.c")
SRCS_RT			= $(shell find $(GNUEFI_DIR)/lib/runtime -maxdepth 1 -type f -name "*.c")
SRCS_MFTAHUEFI	= $(shell find $(SRC_DIR) -type f -name "*.c")

PSF_SRC			= $(SRC_DIR)/core/font.c
RAMDISK_AML_SRC = $(SRC_DIR)/Ramdisk.aml.c

OBJS_GNUEFI		= $(patsubst $(GNUEFI_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS_GNU_EFI) $(SRCS_ARCH) $(SRCS_RT))
OBJS_MFTAHUEFI	= $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS_MFTAHUEFI))

PSF_OBJ			= $(OBJ_DIR)/core/font.o
RAMDISK_AML_OBJ = $(OBJ_DIR)/Ramdisk.aml.o

OBJS			= $(OBJS_GNUEFI) $(OBJS_MFTAHUEFI)

TARGET			= $(BUILD_DIR)/MFTAH.EFI


.PHONY: default clean font debug all ramdisk_ssdt

default: all

clean:
	-rm -rf $(BUILD_DIR)
	$(MAKE) -C ../protocol clean
	env -i PATH="$(PATH)" make -C $(GNUEFI_DIR) clean

# We can assume a 'clean' should be run on all .o files
#   after the build completes. This is because compilation
#   of the EFI file is rather expedient anyway, and it
#   helps not to mix up release and debug build artifacts.
debug: CFLAGS += -DEFI_DEBUG=1
###debug: TARGET = $(TARGET).DEBUG
debug: $(TARGET)

all: $(TARGET)

$(PSF_OBJ):
	-mkdir -p $(shell dirname $@)
	@echo -e "\tXXD\t\tfont.psf"
	xxd -i font.psf >$(PSF_SRC)
	@echo -e "\tCC\t\t$(PSF_SRC)"
	$(CC) $(CFLAGS) -c $(PSF_SRC) -o $(PSF_OBJ)

$(RAMDISK_AML_OBJ): $(SRC_DIR)/Ramdisk.asl
	-mkdir -p $(shell dirname $@)
	@echo -e "\tIASL\t\t$(SRC_DIR)/Ramdisk.asl"
	iasl $(SRC_DIR)/Ramdisk.asl
	echo "unsigned char __attribute__((aligned(8))) NvdimmRootAml[] = {" >$(RAMDISK_AML_SRC)
	cat $(SRC_DIR)/Ramdisk.aml | xxd -i >>$(RAMDISK_AML_SRC)
	echo -ne "};\nunsigned int NvdimmRootAmlLength = " >>$(RAMDISK_AML_SRC)
	wc -c $(SRC_DIR)/Ramdisk.aml | cut -d' ' -f1 | tr -d '\n' >>$(RAMDISK_AML_SRC)
	echo ";" >>$(RAMDISK_AML_SRC)
	@echo -e "\tCC\t\t$(RAMDISK_AML_SRC)"
	$(CC) $(CFLAGS) -c $(RAMDISK_AML_SRC) -o $(RAMDISK_AML_OBJ)

$(TARGET): $(BUILD_DIR) $(PSF_OBJ) $(RAMDISK_AML_OBJ) $(LIBGNUEFI) $(LIBEFI) $(LIBMFTAH) $(OBJS)
	@echo -e "\tLD\t\t$@"
	$(CC) $(LDFLAGS) -o $(TARGET) $(RAMDISK_AML_OBJ) $(PSF_OBJ) $(OBJS) $(LIBMFTAH)

$(BUILD_DIR) $(OBJ_DIR):
	-mkdir -p $(OBJ_DIR)/lib/

$(LIBMFTAH):
	$(MAKE) -C $(MFTAH_DIR) efi

$(LIBEFI): $(LIBGNUEFI)
$(LIBGNUEFI): $(GNUEFI_DIR) $(GNUEFI_DIR)/README.md
	env -i PATH="$(PATH)" make -C $(GNUEFI_DIR) all

%.o: %.c
	-mkdir -p $(dir $@)
	@echo -e "\t\tCC\t$<"
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	-mkdir -p $(dir $@)
	@echo -e "\t\tCC\t$<"
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/lib/%.o: $(GNUEFI_DIR)/lib/%.c
	-mkdir -p $(dir $@)
	@echo -e "\t\tCC\t$<"
	$(CC) $(CFLAGS) -c $< -o $@
