#!/bin/bash
# pipeline_1.sh
echo "Starting pipeline 1 at $(date)"

(yes > /dev/null &) && sleep 2 && kill $!
(tail -f /var/log/syslog &) && sleep 3 && kill $!
(ping 8.8.8.8 > /dev/null &) && sleep 4 && kill $!
(sleep 99999 &) && sleep 1 && kill $!
(dd if=/dev/zero of=/dev/null &) && sleep 2 && kill $!

echo "Finished pipeline 1 at $(date)"
