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

