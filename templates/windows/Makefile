SHELL := /bin/bash

CUR_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
ROOT_DIR := $(CUR_DIR)/../..

$(ROOT_DIR)/venv/bin/ansible-playbook:
	python3 -m venv $(ROOT_DIR)/venv
	$(ROOT_DIR)/venv/bin/python -m pip install ansible==7.1.0 pywinrm

ansible: $(ROOT_DIR)/venv/bin/ansible-playbook

build: ansible
	packer init windows.pkr.hcl
	source $(ROOT_DIR)/venv/bin/activate && packer build -var-file win10.pkrvars.hcl windows.pkr.hcl

import:
	vagrant box remove kafl_windows || true
	vagrant box add packer_windows_libvirt.box --name kafl_windows
