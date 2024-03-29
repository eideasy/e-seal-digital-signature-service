#!/bin/bash

service pcscd start
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start my_first_process: $status"
  exit $status
fi

# Start the second process
java -Dfile.encoding="UTF-8" -jar  eseal.jar
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start my_second_process: $status"
  exit $status
fi

while sleep 1; do
  ps aux |grep pcscd |grep -q -v grep
  PROCESS_1_STATUS=$?
  ps aux |grep java |grep -q -v grep
  PROCESS_2_STATUS=$?
  # If the greps above find anything, they exit with 0 status
  # If they are not both 0, then something is wrong
  if [ $PROCESS_1_STATUS -ne 0 -o $PROCESS_2_STATUS -ne 0 ]; then
    service stop pcscd
    echo "One of the processes has already exited."
    exit 1
  fi
done