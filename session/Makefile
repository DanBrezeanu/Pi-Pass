CC=gcc
SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c,obj/%.o,$(SRCS))
CFLAGS=-std=gnu99 -g
LDFLAGS=../lib
LDLIBS=-lssl -lcrypto -lfastpbkdf2
INCLUDE=-Iinclude/ -I../include -I../crypto/include/ -I../database/include/ -I../storage/include

.PHONY: all

all: $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<