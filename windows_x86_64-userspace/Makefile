compile:
	mkdir -p bin/userspace
	x86_64-w64-mingw32-gcc src/userspace/selffuzz_test.c -I ../ -o bin/userspace/selffuzz_test.exe -mwindows -Wall

init:
	vagrant up --no-provision
	vagrant snapshot save 'ready_provision'

provision:
	vagrant snapshot restore 'ready_provision'
	vagrant provision
	vagrant halt
