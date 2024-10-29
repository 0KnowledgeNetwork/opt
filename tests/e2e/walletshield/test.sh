#!/bin/bash

dir=$(dirname $(realpath "${0}"))
uri=http://localhost:7070
status=0

run_test() {
  test_dir="$1"
  test_case="${test_dir#${dir}}"
  output=$(mktemp)

  if [ -f "${test_dir}/in.json" ]; then
    curl \
      -X POST \
      -H 'Content-Type: application/json' \
      -d "$(cat ${test_dir}/in.json)" \
      --output ${output} \
      --silent \
      "${uri}${test_case}"

    if ! diff "${test_dir}/out.json" ${output} > /dev/null; then
      echo "${test_case}: ❌ failed"
      status=1
    else
      echo "${test_case}: ✅ passed"
    fi
  else
    echo "${test_case}: skipped (test data files not found)"
  fi

  rm -f ${output}
  sleep 1s
}

if [ -z "${1}" ]; then
  for test_dir in $(find "${dir}" -mindepth 1 -type d)
  do
    run_test "${test_dir}"
  done
else
  run_test "${dir}$1"
fi

exit ${status}
