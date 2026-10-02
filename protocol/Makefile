# Makefile for the MFTAH library.
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

SUPPARCHS		= x86_64 x86_64-pc-linux-gnu
# Must be set to one of the members from SUPPARCHS.
ARCH			?= x86_64

CC				= clang

ifeq ($(filter $(ARCH),$(SUPPARCHS)),)
$(error '$(ARCH)' is not a supported architecture for this program.)
endif

SRC_DIR			= src
INCLUDE_DIR		= include
BUILD_DIR		= build
OBJ_DIR			= $(BUILD_DIR)/obj

INCS			= -I$(INCLUDE_DIR)

OPTIM			= -O3
CFLAGS			= -ffreestanding -DMFTAH_ARCH=$(ARCH) -fshort-wchar -mno-red-zone -Wall $(INCS) $(OPTIM) \
					-DMFTAH_RELEASE_DATE=$(shell printf "0x`date +%04Y``date +%02m``date +%02d`")

USES_PIC		= -fPIC

SRCS			= $(wildcard $(SRC_DIR)/*.c)
OBJS			= $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

TARGET			= $(BUILD_DIR)/libmftah.so
TARGET_STATIC	= $(BUILD_DIR)/libmftah.a


.PHONY: default clean debug all efi efi_debug static static_nostr static_debug install

default: all

all: $(TARGET) $(TARGET_STATIC)

clean:
	-rm -rf $(BUILD_DIR)

# We can assume a 'clean' should be run on all .o files
#   after the build completes. This is because compilation
#   of the EFI file is rather expedient anyway, and it
#   helps not to mix up release and debug build artifacts.
debug: CFLAGS += -DMFTAH_LIB_DEBUG=1
debug: $(TARGET)

efi: CFLAGS += -target $(ARCH)-unknown-windows -DMFTAH_WIDE_CHARS=1
efi: CC=clang
efi: USES_PIC=""
efi: clean $(TARGET_STATIC)

efi_debug: CFLAGS += -DMFTAH_LIB_DEBUG=1
efi_debug: efi

static_debug: CFLAGS += -DMFTAH_LIB_DEBUG=1
static_debug: static

static_nostr: CFLAGS += -DMFTAH_LIB_NOSTR=1
static_nostr: static

static: CFLAGS += -target $(ARCH)
static: $(TARGET_STATIC)

all_debug: debug static_debug

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo -e "\t\tCC\t$<"
	$(CC) $(CFALGS) $(USES_PIC) -c $< -o $@

$(BUILD_DIR) $(OBJ_DIR):
	-mkdir -p $(OBJ_DIR)

$(TARGET): $(OBJS)
	@echo -e "\t\tLD\t$(TARGET)"
	$(CC) -shared -o $(TARGET) $(OBJS)

$(TARGET_STATIC): $(OBJS)
	@echo -e "\t\tAR\t$(TARGET_STATIC)"
	ar rcs $(TARGET_STATIC) $(OBJS)

PREFIX				?= /usr/local
install:
	-mkdir -p $(PREFIX)/include/mftah/
	cp $(INCLUDE_DIR)/*.h $(PREFIX)/include/mftah/
	if [ -f "$(TARGET)" ]; then cp -f $(TARGET) $(PREFIX)/lib/; fi
	if [ -f "$(TARGET_STATIC)" ]; then cp -f $(TARGET_STATIC) $(PREFIX)/lib/; fi
	@echo -e "\n\n === libmftah installed ===\n"
