CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -L../target/release -lstoffellang
INCLUDES = -I../include

# Targets
all: ffi_example

ffi_example: ffi_example.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

clean:
	rm -f ffi_example simple_example *.o *.so *.dylib *.dll core

test: ffi_example
	LD_LIBRARY_PATH=../target/release ./ffi_example

.PHONY: clean test all