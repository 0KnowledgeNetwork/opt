#!/bin/bash -e

# This script is invoked by ./Makefile to generate a docker-compose.yml file
# for a local test network using appchain pki. Variables set by the Makefile
# are read from the environment.

port=30000
dir_out=${net}

echo "Generating config files for local network:"
echo "  dir_base: ${dir_base}"
echo "  dir_bin: ${dir_bin}"
echo "  dir_out: ${dir_out}"
echo "  docker_image: ${docker_image}"
echo "  docker_image_agent: ${docker_image_agent}"
echo "  num_gateways: ${num_gateways}"
echo "  num_servicenodes: ${num_servicenodes}"
echo "  num_mixes: ${num_mixes}"

gencfg="${docker} run ${docker_args} --rm \
  --volume $(readlink -f ./network.yml):/tmp/network.yml \
  --volume $(readlink -f ${dir_out}):${dir_base} \
  ${docker_image} \
  ${dir_bin}/genconfig \
    -input /tmp/network.yml \
    -binary-prefix ${dir_bin}/ \
    -dir-base ${dir_base} \
    -dir-out ${dir_base}"

echo "genconfig: ${gencfg}"

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
  image: ${docker_image}
  user: ${docker_user}
  volumes:
    - ${dir_out}:${dir_base}
  network_mode: host

services:

  metrics:
    restart: "no"
    image: docker.io/prom/prometheus
    volumes:
      - ${dir_out}:${dir_base}
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
  ${id}-agent:
    <<: *common-service
    image: ${docker_image_agent}
    command: >
      pnpm run agent \
        --ipfs \
        --ipfs-data ${dir_base}/ipfs-data \
        --listen \
        --key ${dir_base}/${id}-auth/appchain.key \
        --socket ${dir_base}/${id}-auth/appchain.sock \
        --socket-format cbor \
        --tx-status-retries 20 \
        --debug

  ${id}-auth:
    <<: *common-service
    command: ${dir_bin}/pki -f ${dir_base}/${id}-auth/authority.toml
    depends_on:
      - ${id}-agent

  ${id}:
    <<: *common-service
    command: ${dir_bin}/server -f ${dir_base}/${id}/katzenpost.toml
    depends_on:
      - ${id}-auth

EOF
}

for i in $(seq 1 ${num_gateways}); do gencfg_node gateway ${i}; done
for i in $(seq 1 ${num_servicenodes}); do gencfg_node servicenode ${i}; done
for i in $(seq 1 ${num_mixes}); do gencfg_node mix ${i}; done
