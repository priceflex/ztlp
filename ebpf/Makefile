# ZTLP XDP eBPF — Build System
#
# Requirements:
#   clang (>= 11), llvm, libbpf-dev, linux-headers
#
# Usage:
#   make           — Build XDP object and loader
#   make clean     — Remove build artifacts

CLANG      ?= clang
GCC        ?= gcc
LLC        ?= llc

BPF_CFLAGS := -O2 -target bpf -g \
              -D__TARGET_ARCH_x86 \
              -Wall -Werror

LOADER_CFLAGS  := -O2 -Wall -Werror
LOADER_LDFLAGS := -lbpf -lelf -lz

# Kernel headers (auto-detect)
KERN_HEADERS := /usr/include
BPF_CFLAGS   += -I$(KERN_HEADERS)

.PHONY: all clean

all: ztlp_xdp.o ztlp-xdp-loader

# BPF object — compiled with clang targeting BPF
ztlp_xdp.o: ztlp_xdp.c ztlp_xdp.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Userspace loader — compiled with gcc, linked against libbpf
ztlp-xdp-loader: loader.c ztlp_xdp.h
	$(GCC) $(LOADER_CFLAGS) -o $@ $< $(LOADER_LDFLAGS)

clean:
	rm -f ztlp_xdp.o ztlp-xdp-loader
