# Makefile for the MFTAH library.
#
# Zack Puhl <zack@crows.dev>
# 2024-10-17
# 
# Copyright (C) 2024 Zack Puhl
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

SUPPARCHS		:= x86_64

# Must be set to one of the members from SUPPARCHS.
ARCH			:= x86_64

CXX				= clang

ifeq ($(filter $(ARCH),$(SUPPARCHS)),)
$(error '$(ARCH)' is not a supported architecture for this program.)
endif

SRC_DIR			= src
INCLUDE_DIR		= src/include
BUILD_DIR		= build

INCS		= -I./ -I./src -I$(INCLUDE_DIR)

OPTIM			= -O3
CFLAGS			= -ffreestanding -DMFTAH_ARCH=$(ARCH) -fshort-wchar -mno-red-zone -Wall $(INCS_DIR) $(OPTIM) \
					-DMFTAH_RELEASE_DATE=$(shell printf "0x`date +%04Y``date +%02m``date +%02d`")

USES_PIC		= -fPIC

SRCS			= $(shell find $(SRC_DIR) -maxdepth 1 -type f -name "*.c")
OBJS			= $(patsubst %.c,%.o,$(SRCS))

TARGET			= $(BUILD_DIR)/libmftah.so
TARGET_STATIC	= $(BUILD_DIR)/libmftah.a


.PHONY: default
.PHONY: clean
.PHONY: clean-objs
.PHONY: debug
.PHONY: all
.PHONY: efi
.PHONY: efi_debug
.PHONY: static
.PHONY: static_nostr
.PHONY: static_debug
.PHONY: install

default: all

clean:
	-rm $(TARGET)* &>/dev/null
	-rm $(TARGET_STATIC)* &>/dev/null
	-rm $(OBJS) &>/dev/null	

clean-objs:
	-rm $(OBJS) &>/dev/null

# We can assume a 'clean' should be run on all .o files
#   after the build completes. This is because compilation
#   of the EFI file is rather expedient anyway, and it
#   helps not to mix up release and debug build artifacts.
debug: CFLAGS += -DMFTAH_LIB_DEBUG=1
debug: $(TARGET)

efi: CFLAGS += -target $(ARCH)-unknown-windows -DMFTAH_WIDE_CHARS=1
efi: CXX=clang
efi: USES_PIC=""
efi: $(TARGET_STATIC)

efi_debug: CFLAGS += -DMFTAH_LIB_DEBUG=1
efi_debug: efi

static_debug: CFLAGS += -DMFTAH_LIB_DEBUG=1
static_debug: static

static_nostr: CFLAGS += -DMFTAH_LIB_NOSTR=1
static_nostr: static

static: CFLAGS += -target $(ARCH)
static: $(TARGET_STATIC)

all: $(TARGET) $(TARGET_STATIC)

all_debug: debug static_debug

# Kind of silly, but we only need to compile a single object file.
src/mftah.o:
	-mkdir -p $(BUILD_DIR)
	$(CXX) $(CFLAGS) $(USES_PIC) -c -o src/mftah.o src/mftah.c

# DSO
$(TARGET): src/mftah.o
	$(CXX) -shared -o $(TARGET) src/mftah.o

# Archive
$(TARGET_STATIC): src/mftah.o
	ar rcs $(TARGET_STATIC) src/mftah.o

# Install
install:
	@cp $(INCLUDE_DIR)/*.h /usr/local/include/
	-@cp -f $(TARGET) /usr/local/lib/
	-@cp -f $(TARGET_STATIC) /usr/local/lib/
	@echo -e "\n\n === libmftah installed ===\n"
