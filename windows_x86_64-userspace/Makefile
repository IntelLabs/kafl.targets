SHELL := /bin/bash

compile:
	mkdir -p bin/{userspace,driver}
	x86_64-w64-mingw32-gcc src/userspace/selffuzz_test.c -I ../ -o bin/userspace/selffuzz_test.exe -Wall -mwindows 
	x86_64-w64-mingw32-gcc src/driver/vuln_test.c -I ../ -o bin/driver/vuln_test.exe -Wall -lntdll -lpsapi

init:
	vagrant up --no-provision
	vagrant snapshot save 'ready_provision'

provision:
	vagrant snapshot restore 'ready_provision'
	vagrant provision
	vagrant halt
