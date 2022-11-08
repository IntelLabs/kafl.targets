NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)

CFLAGS += -static -g -I$(NYX_INCLUDE_PATH)

vmcall: src/vmcall.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f vmcall

tags:
	ctags -R src
