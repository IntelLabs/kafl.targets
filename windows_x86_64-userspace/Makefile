compile:
	mkdir -p bin
	x86_64-w64-mingw32-gcc src/selffuzz_test.c -I ../ -o bin/selffuzz_test.exe -mwindows -Wall

init:
	vagrant up --no-provision
	vagrant snapshot save 'ready_provision'

provision:
	vagrant snapshot restore 'ready_provision'
	vagrant provision
	vagrant halt
