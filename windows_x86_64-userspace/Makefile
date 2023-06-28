SHELL := /bin/bash

CUR_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
ROOT_DIR := $(CUR_DIR)/../

$(ROOT_DIR)/venv/bin/ansible-playbook:
	python3 -m venv $(ROOT_DIR)/venv
	$(ROOT_DIR)/venv/bin/python -m pip install ansible==7.1.0 pywinrm

ansible: $(ROOT_DIR)/venv/bin/ansible-playbook

init:
	vagrant up --no-provision
	vagrant snapshot save 'ready_provision'

compile:
	mkdir -p bin/{userspace,driver}
	x86_64-w64-mingw32-gcc src/userspace/selffuzz_test.c -I ../ -o bin/userspace/selffuzz_test.exe -Wall -mwindows 
	x86_64-w64-mingw32-gcc src/driver/vuln_test.c -I ../ -o bin/driver/vuln_test.exe -Wall -lntdll -lpsapi

provision_userspace: compile ansible
	vagrant snapshot restore 'ready_provision'
	TARGET_HARNESS='userspace' vagrant provision
	vagrant halt

provision_driver: compile ansible
	vagrant snapshot restore 'ready_provision'
	TARGET_HARNESS='driver' vagrant provision
	vagrant halt
