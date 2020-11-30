CC	  := $(CROSS_COMPILE)gcc
MKDIR := mkdir -p
RM    := rm -rf

BUILDDIR  := build
SRCDIR    := src
TESTDIR   := tests
VENDORDIR := vendor

SRCDIRS  := $(wildcard $(SRCDIR)/*)
OBJDIRS  := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SRCDIRS))

SRCS := $(foreach srcdir,$(SRCDIRS),$(wildcard $(srcdir)/*.c))
OBJS := $(patsubst src/%.c,$(BUILDDIR)/%.o,$(SRCS))

VENDOR_DIRS := $(wildcard $(VENDORDIR)/*)

VENDOR_INCLUDE_DIRS := $(patsubst %,%/include,$(VENDOR_DIRS))
EXTRA_INCLUDE_DIRS  := /usr/include/python3.7
INCLUDE_DIRS	    := $(patsubst %,%/include,$(SRCDIRS)) $(SRCDIR)/include \
					   $(EXTRA_INCLUDE_DIRS) $(VENDOR_INCLUDE_DIRS)

VENDOR_LIB_DIRS     := $(patsubst %,%/lib,$(VENDOR_DIRS))		   
LIB_DIRS 		    := lib/ /usr/lib/python3.7/ $(VENDOR_LIB_DIRS)

INCLUDE := $(patsubst %,-I%,$(INCLUDE_DIRS))
LIBS    := ssl crypto fastpbkdf2 pigpio pthread rt r502 python3.7m serialport

CFLAGS  := -g -std=gnu99
LDFLAGS := $(patsubst %,-L%,$(LIB_DIRS))
LDLIBS  := $(patsubst %,-l%,$(LIBS))

TARGET	:= pipass

TEST_BUILDDIR := $(TESTDIR)/build
TEST_SRCS     := $(wildcard $(TESTDIR)/*.c)
TEST_OBJS     := $(patsubst $(TESTDIR)/%.c,$(TEST_BUILDDIR)/%.o,$(TEST_SRCS))
TEST_LIBS     := m check subunit
TEST_LDLIBS   := $(patsubst %,-l%,$(TEST_LIBS))
TEST_TARGET   := test_$(TARGET)

.PHONY: all test clean createdirs

all: createdirs $(OBJS)
	@echo "   LD $(TARGET)"
	@$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET) $(LDLIBS)
	

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@echo "   CC  $^" 
	@$(CC) $(CFLAGS) $(INCLUDE) $< -c -o $@


test: createdirs $(OBJS) $(TEST_OBJS)
	$(CC) $(OBJS) $(TEST_OBJS) $(LDFLAGS) -o $(TEST_TARGET) $(LDLIBS) $(TEST_LDLIBS)
	@echo "Running tests..."
	@sudo ./$(TEST_TARGET)

$(TEST_BUILDDIR)/%.o: $(TESTDIR)/%.c
	@echo "   CC  $^" 
	@$(CC) $(CFLAGS) $(INCLUDE) $< -c -o $@

clean:
	$(RM) $(BUILDDIR) $(TARGET) $(TEST_BUILDDIR)
	
createdirs:
	$(info $(LDLIBS))
	@$(MKDIR) $(BUILDDIR) $(OBJDIRS) $(TEST_BUILDDIR)

