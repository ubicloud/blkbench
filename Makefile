CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -pedantic
LDFLAGS ?=

PKG_CFLAGS  := $(shell pkg-config --cflags blkio)
PKG_LDFLAGS := $(shell pkg-config --libs blkio)

SRCS := blkbench.c test_hist.c test_funcs.c poc.c

.PHONY: all clean test test-output test-unit test-cli test-smoke lint format

all: blkbench

blkbench: blkbench.c
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -o $@ $< $(LDFLAGS) $(PKG_LDFLAGS) -lpthread -lm

poc: poc.c
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -o $@ $< $(LDFLAGS) $(PKG_LDFLAGS)

test_hist: test_hist.c
	$(CC) $(CFLAGS) -o $@ $< -lm

test_funcs: test_funcs.c
	$(CC) $(CFLAGS) -o $@ $< -lm

test-unit: test_hist test_funcs
	./test_hist
	./test_funcs

test-cli: blkbench
	bash test_cli.sh

test-smoke: blkbench
	bash test_output.sh

test: test-unit test-cli test-smoke

lint:
	clang-format --dry-run -Werror $(SRCS)

format:
	clang-format -i $(SRCS)

clean:
	rm -f blkbench poc test_hist test_funcs
