#!/usr/bin/env bash

set -e

BENCH_ZERO="$1"
BENCH_LOAD="$2"
BENCH_INSTR="$3"
REPT_COUNT="$4"

PERF="perf stat -r 100 -e cycles:u,instructions:u,task-clock:u -j -- "

mapfile -t array <<< $($PERF $BENCH_ZERO |& jq -r '."counter-value", .unit')
CYCLES_ZERO=${array[0]%%\.0*}
INSTRUCTIONS_ZERO=${array[2]%%\.0*}
TASK_CLOCK_ZERO=${array[4]}

TASK_CLOCK_UNITS=${array[5]}

mapfile -t array <<< $($PERF $BENCH_LOAD |& jq -r '."counter-value", .unit')
CYCLES_LOAD=${array[0]%%\.0*}
INSTRUCTIONS_LOAD=${array[2]%%\.0*}
TASK_CLOCK_LOAD=${array[4]}

CYCLES=$(($CYCLES_LOAD - $CYCLES_ZERO))
INSTRUCTIONS=$(($INSTRUCTIONS_LOAD - $INSTRUCTIONS_ZERO))
AVG_CYCLES=$(echo "scale=3; $CYCLES / $REPT_COUNT" | bc)

TASK_CLOCK=$(echo "scale=3; $TASK_CLOCK_LOAD - $TASK_CLOCK_ZERO" | bc)

echo "|\`$BENCH_INSTR\`| $AVG_CYCLES | $TASK_CLOCK $TASK_CLOCK_UNITS |"

