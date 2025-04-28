#!/bin/bash
# pipeline_2.sh
echo "Starting pipeline 2 at $(date)"

(yes > /dev/null &) && sleep 1 && kill $!
(top -b > /dev/null &) && sleep 3 && kill $!
(ping 1.1.1.1 > /dev/null &) && sleep 2 && kill $!
(sleep 99999 &) && sleep 4 && kill $!
(tail -f /var/log/kern.log &) && sleep 1 && kill $!

echo "Finished pipeline 2 at $(date)"
