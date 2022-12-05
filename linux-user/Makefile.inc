# Common steps for linux-user/ projects

ifeq ($(EXAMPLES_ROOT),)
$(error $$EXAMPLES_ROOT is not set - did you activate kAFL env?)
endif

ifeq ($(KAFL_WORKDIR),)
$(error $$KAFL_WORKDIR is not set - did you activate kAFL env?)
endif

NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)
LIBNYX_AGENT_ROOT ?= $(EXAMPLES_ROOT)/linux-user/libnyx_agent

