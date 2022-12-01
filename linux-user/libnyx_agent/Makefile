all: debug

include ../Makefile.inc

CFLAGS += -Wall -Werror -I$(NYX_INCLUDE_PATH)

TARGET=libnyx_agent

release: CFLAGS += -O2
release: $(TARGET).so $(TARGET).a

debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET).so $(TARGET).a


src/nyx_agent.o: src/nyx_agent.c
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -c $^ -o $@ $(LIBS)

$(TARGET).so: src/nyx_agent.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fPIC $^ -o $@ $(LIBS)

$(TARGET).a: src/nyx_agent.o
	ar rcs $@ $^

clean:
	rm -f $(TARGET).so $(TARGET).a src/nyx_agent.o

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
