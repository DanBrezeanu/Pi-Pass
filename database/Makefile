CC=gcc
OBJ_DIR=obj
CUR_DIR=$(notdir $(shell pwd))
SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c, $(OBJ_DIR)/%.o,$(SRCS))
CFLAGS=-std=gnu99 -g
INCLUDE=-Iinclude/ $(shell find ../ -name 'include' -type d -exec sh -c 'echo -I{}' \;)
RM=rm -rf

.PHONY: all clean

all: $(OBJS)

$(OBJ_DIR)/%.o: %.c
	@echo "CC $^" 
	@$(CC) $(CFLAGS) $(INCLUDE) $< -c -o $@

clean:
	@echo "CLEAN $(CUR_DIR)"
	@$(RM) -rf $(OBJ_DIR)/*.o
