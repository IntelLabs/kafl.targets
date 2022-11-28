# common definitions for inclusion by other projects
LIBNYX_AGENT_ROOT ?= $(EXAMPLES_ROOT)/linux-user/libnyx_agent
LIBNYX_AGENT_INCLUDE ?= $(LIBNYX_AGENT_ROOT)/src
LIBNYX_AGENT_LIB ?= $(LIBNYX_AGENT_ROOT)/libnyx_agent.so

# use these in your project
LIBNYX_AGENT_INCLUDE := $(LIBNYX_AGENT_INCLUDE)
LIBNYX_AGENT_STATIC := -Wl,-Bstatic -L$(LIBNYX_AGENT_ROOT) -l:libnyx_agent.a -Wl,-Bdynamic
LIBNYX_AGENT_DYNAMIC := -L$(LIBNYX_AGENT_ROOT) -llibnyx_agent

LIBNYX_AGENT_BUILD:
	$(MAKE) -C $(LIBNYX_AGENT_ROOT)

.PHONY: LIBNYX_AGENT_BUILD

