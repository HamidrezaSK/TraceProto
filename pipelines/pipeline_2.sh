#!/bin/bash
# pipeline_2.sh
echo "Starting pipeline 2 at $(date)"

uptime > /dev/null &
PID1=$!

vmstat 1 5 > /dev/null &
PID2=$!

cat /proc/cpuinfo > /dev/null &
PID3=$!

free -m > /dev/null &
PID4=$!

sleep 99999 &
PID5=$!

sleep 1
kill $PID1

sleep 2
kill $PID2

sleep 3
kill $PID3

sleep 1
kill $PID4

sleep 2
kill $PID5

echo "Finished pipeline 2 at $(date)"
