# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
CLANG: clang
all: trace

.PHONY: clean $(CLANG) $(LLC)

clean:
        rm -f *.o
        rm -f *.ll
        rm -f *~

trace: %: %.c Makefile
        clang \
            -target bpf \
            -I /usr/include/bpf \
            -Wall -D DEBUG \
            -O2 -c -o trace.o $<

