#!/bin/bash

# payload size in bytes
size=${1:-30000}

string=$(head -c ${size} </dev/urandom | base64 | head -c ${size})

curl -i -X POST -H "Content-Type: application/json" -d "${string}" --output - http://localhost:7070/nada
