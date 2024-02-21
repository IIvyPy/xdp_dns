# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
CLANG = clang
DEBUG ?= n
EDNS0 ?= y

ifeq ($(DEBUG),y)
	BPF_EXTRA_FLAGS += -D DEBUG
endif

ifeq ($(EDNS0), y)
	BPF_EXTRA_FLAGS += -D EDNS0
endif


.PHONY: clean $(CLANG) $(LLC)

all: trace

clean:
		rm -f *.o
		rm -f *.ll
		rm -f *~

trace: %: %.c Makefile
		clang \
			-g \
            -target bpf \
            -I /usr/include/bpf \
            -Wall $(BPF_EXTRA_FLAGS) \
            -O2 -c -o trace.o $<

