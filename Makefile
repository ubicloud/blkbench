CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -pedantic
LDFLAGS ?=

PKG_CFLAGS  := $(shell pkg-config --cflags blkio)
PKG_LDFLAGS := $(shell pkg-config --libs blkio)

.PHONY: all clean test test-output

all: lblk-bench

lblk-bench: lblk-bench.c
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -o $@ $< $(LDFLAGS) $(PKG_LDFLAGS) -lpthread -lm

poc: poc.c
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -o $@ $< $(LDFLAGS) $(PKG_LDFLAGS)

test_hist: test_hist.c
	$(CC) $(CFLAGS) -o $@ $< -lm

test: test_hist
	./test_hist

test-output: lblk-bench
	bash test_output.sh

clean:
	rm -f lblk-bench poc test_hist
