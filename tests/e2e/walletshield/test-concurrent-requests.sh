#!/bin/bash

dir=$(dirname $(realpath "${0}"))
status=0

run_test() {
  ${dir}/test.sh | while read -r line; do
    echo "[${1}] $line"
    if [[ "$line" == *"failed"* ]]; then
      echo "Test failed, stopping all processes..."
      kill 0 # Kill all background jobs if failure detected
      status=1
    fi
  done
}

# Run multiple instances of the test script in the background
for i in {1..2}; do
  run_test ${i} &
done

wait
exit ${status}
