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

SRC_DIR				= src
BUILD_DIR			= build
OBJ_DIR				= $(BUILD_DIR)/obj

LIBMFTAH_BUILD_DIR	= ../protocol/build
LIBMFTAH_STATIC		= $(LIBMFTAH_BUILD_DIR)/libmftah.a
LIBMFTAH_INC_DIR	= ../protocol/include

CC					= clang
CFLAGS				= -Wall -Wpedantic -Wextra \
						-I$(LIBMFTAH_INC_DIR) \
						-DMFTAH_ARCH=$(ARCH) \
						-DMFTAH_RELEASE_DATE=$(shell printf "0x`date +%04Y``date +%02m``date +%02d`")
DEBUG_FLAGS			= -O0 -g3 \
						-fsanitize=address \
						-DMFTAHCRYPT_DEBUG=1
RELEASE_FLAGS		= -s -g0 -O3 -flto=auto
LDFLAGS				= -lm -lpthread -L$(LIBMFTAH_BUILD_DIR) -lmftah

SRCS				= $(shell find $(SRC_DIR) -maxdepth 1 -type f -name "*.c")
OBJS				= $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

TARGET				= $(BUILD_DIR)/mftahcrypt
LIBMFTAH_TARGET		= static


.PHONY: default clean release debug install

default: release

clean:
	-rm -rf $(BUILD_DIR)
	$(MAKE) -C ../protocol clean

release: CFLAGS += $(RELEASE_FLAGS)
release: $(TARGET)

debug: CFLAGS += $(DEBUG_FLAGS)
debug: LDFLAGS += -fsanitize=address
debug: LIBMFTAH_TARGET = static_debug
debug: $(TARGET)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo -e "\tCC\t\t$<"
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR) $(OBJ_DIR):
	-@mkdir -p $(OBJ_DIR)

$(TARGET): $(OBJS) $(LIBMFTAH_STATIC)
	@echo -e "\tLD\t\t$<"
	$(CC) $(LIBS) -o $(TARGET) $(OBJS) $(LDFLAGS)

$(LIBMFTAH_STATIC):
	$(MAKE) -C ../protocol $(LIBMFTAH_TARGET)

PREFIX				?= /usr/local/bin
install: $(TARGET)
	chmod 755 $(TARGET)
	cp -f $(TARGET) $(PREFIX)/mftahcrypt
	@echo -e "\n\n=== MFTAHCRYPT installed to $(PREFIX)/ ===\n"
