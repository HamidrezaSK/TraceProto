#!/bin/bash
# pipeline_1.sh
echo "Starting pipeline 1 at $(date)"

yes > /dev/null &
PID1=$!

tail -f /var/log/syslog &
PID2=$!

sleep 99999 &
PID3=$!

dd if=/dev/zero of=/dev/null &
PID4=$!

top -b > /dev/null &
PID5=$!

sleep 2
kill $PID1

sleep 2
kill $PID2

sleep 3
kill $PID3

sleep 1
kill $PID4

sleep 2
kill $PID5

echo "Finished pipeline 1 at $(date)"