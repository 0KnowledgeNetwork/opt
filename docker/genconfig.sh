#!/bin/bash

# This script is invoked by ./Makefile to generate config files for a local
# test network using appchain pki. Variables set by the Makefile are read from
# the environment. This is intended to be run from within the katzenpost docker
# container.

port=30000
dir_base="/${net_name}"
dir_out=${dir_base}
binary_suffix=".${distro}"

rm -rf ${dir_out} && mkdir -p ${dir_out}

echo "Generating config files for local network:"
echo "  num gateways: ${gateways}"
echo "  num servicenodes: ${serviceNodes}"
echo "  num mixes: ${mixes}"
echo "  binary-suffix: ${binary_suffix}"
echo "  distro: ${distro}"
echo "  dir-base: ${dir_base}"
echo "  dir-out: ${dir_out}"

gencfg="../genconfig/cmd/genconfig/genconfig \
  -input ./network.yml \
  -binary-suffix ${binary_suffix} \
  -dir-base ${dir_base} \
  -dir-out ${dir_out}"

cat <<EOF > ${dir_out}/prometheus.yml
scrape_configs:
- job_name: katzenpost
  scrape_interval: 1s
  static_configs:
  - targets:
EOF

cat <<EOF > ${dir_out}/docker-compose.yml
x-common-service: &common-service
  restart: "no"
  image: katzenpost-${distro}_base
  volumes:
    - ./:${dir_base}
  network_mode: host

services:

  metrics:
    restart: "no"
    image: docker.io/prom/prometheus
    volumes:
      - ./:${dir_base}
    command: --config.file="${dir_base}/prometheus.yml"
    network_mode: host

EOF

function gencfg_node () {
  type=${1}
  id=${type}${2}

  ${gencfg} -port ${port} -type ${type} -identifier ${id} || exit 1

  echo "    - 127.0.0.1:${port}" >> ${dir_out}/prometheus.yml
  port=$((port+2))

  cat <<EOF >> ${dir_out}/docker-compose.yml
  ${id}-auth:
    <<: *common-service
    command: ${dir_base}/pki${binary_suffix} -f ${dir_base}/${id}-auth/authority.toml

  ${id}:
    <<: *common-service
    command: ${dir_base}/server${binary_suffix} -f ${dir_base}/${id}/katzenpost.toml
    depends_on:
      - ${id}-auth

EOF
}

for i in $(seq 1 ${gateways}); do gencfg_node gateway ${i}; done
for i in $(seq 1 ${serviceNodes}); do gencfg_node servicenode ${i}; done
for i in $(seq 1 ${mixes}); do gencfg_node mix ${i}; done

# FIXME: client*/config.toml generated with, to include, gateway('s auth)
# ${gc} -type client1
# ${gc} -type client2
