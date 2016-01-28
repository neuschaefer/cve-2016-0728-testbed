CFLAGS=-Wall -g -O2 -lkeyutils -fno-omit-frame-pointer -std=c99 -lbsd

all: test msgfoo

clean:
	rm -f test msgfoo

.PHONY: all clean
