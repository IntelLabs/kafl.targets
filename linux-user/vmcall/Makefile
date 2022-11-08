NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)

CFLAGS += -g -Og -I$(NYX_INCLUDE_PATH)

static: CFLAGS += -static
static: vmcall

debug: CFLAGS += -fsanitize=address,undefined -DDEBUG
debug: vmcall

all: vmcall

vmcall: src/vmcall.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f vmcall

tags:
	ctags -R src
