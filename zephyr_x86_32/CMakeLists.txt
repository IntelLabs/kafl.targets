# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(kafl_agent LANGUAGES C)
set_property(TARGET app PROPERTY C_STANDARD 99)

target_sources(app PRIVATE src/main.c)

# Select a fuzzing target at a time, e.g. ``cmake ../ -D KAFL_TEST=y''
target_sources_ifdef(KAFL_TEST  app PRIVATE src/target_test.c)
target_sources_ifdef(KAFL_FS    app PRIVATE src/target_fs.c)
target_sources_ifdef(KAFL_JSON  app PRIVATE src/target_json.c)
