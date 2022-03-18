# kAFL for Zephyr Example

This folder contains example agents and helper scripts to get started with
fuzzing Zephyr with kAFL.

## Quick Steps

The [run.sh](run.sh) helper script encapsulates the main use cases for download, build,
fuzzing, as well as coverage and debug execution of a Zephyr target inside kAFL.

It is meant to run from the kAFL root folder, like so:

```
./examples/zephyr_x86_32/run.sh zephyr       # fetch dependencies and install Zephyr (large!)
./examples/zephyr_x86_32/run.sh build TEST   # build the `TEST` application
./examples/zephyr_x86_32/run.sh fuzz -p 2    # fuzz the currently build application
```

By default, the fuzzer is launched with a temporary work directory in `/dev/shm/kafl_zephyr`
and only prints limited status updates to the console. You can inspect the status of an
ongoing or finished campaign using a number of tools:

```
WORKDIR=/dev/shm/kafl_zephyr # fuzzer workdir
kafl_gui.py $WORKDIR         # interactive UI
kafl_plot.py $WORKDIR        # print payloads discovered over time
gnuplot -c $KAFL_ROOT/scripts/stats.plot $WORKDIR/stats.csv # plot fuzzer status
mcat.py $KAFL_ROOT/config    # view detailed fuzzer configuration
```

The launch script encapsulates some more typical use cases (execute based on existing workdir!):

```
# collect coverage information
./examples/zephyr_x86_32/run.sh cov $WORKDIR
# launch first crashing payload in a debug session (qemu -s -S)
./examples/zephyr_x86_32/run.sh debug $WORKDIR/corpus/crash/payload_00001
```

## Zephyr RTOS + SDK Install

Quick steps captured below, check the latest Zephyr guides for detailed
information.

### Environment/Dependencies Setup

https://docs.zephyrproject.org/latest/getting_started/installation_linux.html

```
$ sudo apt-get update
$ sudo apt-get upgrade
$ sudo apt-get install --no-install-recommends git cmake ninja-build gperf ccache dfu-util \
   device-tree-compiler wget python3-pip python3-setuptools python3-wheel python3-yaml \
   xz-utils file make gcc gcc-multilib

# missing deps on Ubuntu..?
$ sudo apt-get install python3-pyelftools
```

Note that Zephyr needs a recent cmake. Version 3.13.1 at the time of writing.

### Zephyr Getting Started Guide

https://docs.zephyrproject.org/latest/getting_started/index.html

```
# install west
$ pip3 install --user west
$ which west || echo "Error: ~/.local/bin not in \$PATH?"

$ west init zephyrproject
$ cd zephyrproject
$ west update

# fetch python req's
$ pip3 install --user -r zephyr/scripts/requirements.txt

# activate host' toolchain
$ cd zephyr
$ export ZEPHYR_TOOLCHAIN_VARIANT=host
$ source zephyr-env.sh
```

If you have trouble building the hello world sample, try using the Zephyr SDK:

```
$ wget https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.11.2/zephyr-sdk-0.11.2-setup.run
$ bash zephyr-sdk-0.11.2-setup.run

$ source zephyr-env.sh
```

Note that for the provided script [run.sh](run.sh)
to work, you have to install the zephyr-SDK to the default directory (`$HOME/zephyr-sdk/`)
and create a `.zephyrrc` file in the `$HOME` directory.

## Launching Zephyr RTOS

To launch Zephyr you need to build a particular application which will be run as
the main thread. Zephyr will not do anything useful if that application is
missing.

### Build and run application in Qemu

Start building the Zephyr hello world. We need to have this running in a qemu
environment that is compatible with the later kAFL Qemu setup. In particular,
this means our target app should work with -enable-kvm. Also note the required
RAM and any other dependencies at this point.

```
# build hello world and attempt to run with host side qemu-86
$ west build -b qemu_x86 samples/hello_world
$ cd build
$ ninja run

$ ps aux|grep qemu # note commandline

# confirm it running with KVM and minimum other parameters
$ qemu -kernel zephyr.elf -enable-kvm -m 16 [...]
```

### Build and run Zephyr-based kAFL Agent

To fuzz Zephyr or one of its components, we need to integrate a kAFL agent into
the guest VM. The agent communicates with kAFL to receive a fuzz input and
deliver it to the desired test target.

We provide two examples: The `TEST` application implements its own target_test()
function which contains known bugs. The fuzzer will quickly find the inputs that
cause this function to crash. The `JSON` application calls the json parser of
Zephyr to process the fuzzer input, thus fuzzing the json parser.

```
$ cd path/to/zephyr/agent
$ mkdir build; cd build
$ cmake ../ -D KAFL_TEST=y''
$ make
```

Test the build using the patched Qemu+KVM. We expect it to fail on the
hypercalls since the kAFL frontend is missing. However, we can confirm at this
point that the agent actually starts and attempts to connect to kAFL as
expected. We can also identify the minimum qemu commandline required to boot
Zephyr and potentially adjust the configuration used by kAFL.

```
$ qemu-system-x86_64 -serial mon:stdio -enable-kvm -m 16 -nographic -no-reboot -no-acpi \
   -kernel build/zephyr/zephyr.elf -no-reboot -no-acpi -D qemu_logfile.log
```

Start the fuzzer in -kernel mode, using the compiled Zephyr kernel with
integrated fuzzing agent as the payload (will be the argment to 'qemu -kernel').
Currently need to provide fake VM snapshot files to make the parser happy.

The IP range can be determined from `build/zephyr.map` and should include the subsystem
you are trying to fuzz. Typically we can just use the entire `.text` segment here
since Zephyr strips any unnecessary functionality at build time and will not
have any undesired background activity outside our fuzzing loop.

```
$ python kafl_fuzz.py -ip0 0x0000000000102af1-0x000000000010ad52 \
   -mem 16 -extra ' -no-reboot -no-acpi' \
   -kernel targets/zephyr_x86_32/build/zephyr/zephyr.elf \
   -seed_dir seed/kafl_vulntest/ \
   -work_dir /dev/shm/kafl_zephyr \
   --purge -v
```
