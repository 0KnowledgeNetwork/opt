warped?=true
mixes=3
auths=3
gateways=1
serviceNodes=1

UserForwardPayloadLength=30000

distro=alpine
net_name=voting_mixnet
docker_compose_yml=$(net_name)/docker-compose.yml
sh=$(shell if echo ${distro}|grep -q alpine; then echo sh; else echo bash; fi)
SHELL=/bin/bash
cache_dir=cache
log_level=DEBUG
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"
uid?=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid?=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker_args=--user ${docker_user} --volume $(shell readlink -f $(katzenpost_dir)):/go/katzenpost --workdir /go/katzenpost
mount_net_name=-v $(katzenpost_dir)/docker/$(net_name):/$(net_name)
mount_opt=-v $(shell readlink -f ..):/go/opt
docker_run_sh=$(docker) run ${docker_args} $(mount_net_name) $(mount_opt) --rm katzenpost-$(distro)_base $(sh) -c

katzenpost_dir=/tmp/katzenpost.opt
katzenpost_version=$(shell grep -E '^	github.com/katzenpost/katzenpost ' ../go.mod | awk '{print $$2}')
net_dir=$(katzenpost_dir)/docker/$(net_name)

# export variables to the environment for consumption by invoked Makefile(s)
export

.PHONY: custom-binaries
custom-binaries: $(net_dir)/http_proxy.$(distro)

.PHONY: clone-katzenpost
clone-katzenpost:
	@if [ ! -d "$(katzenpost_dir)" ]; then \
		git clone \
			--branch $(katzenpost_version) \
			--depth 1 \
			--single-branch \
			https://github.com/katzenpost/katzenpost.git \
			$(katzenpost_dir); \
	fi

.PHONY: custom-genconfig
custom-genconfig:
	cp ../genconfig/main.go $(katzenpost_dir)/genconfig/main.go

$(net_dir)/http_proxy.$(distro): $(katzenpost_dir)/docker/$(distro)_base.stamp | $(net_name)
	$(docker_run_sh) 'cd /go/opt/server_plugins/cbor_plugins/http_proxy/cmd/http_proxy ; go build -trimpath -ldflags ${ldflags} && mv http_proxy /$(net_name)/http_proxy.$(distro)'
	cp ../server_plugins/cbor_plugins/http_proxy/http_proxy_config.toml $(net_dir)/servicenode1/

$(net_dir)/walletshield.$(distro): $(katzenpost_dir)/docker/$(distro)_base.stamp | $(net_name)
	$(docker_run_sh) 'cd /go/opt/apps/walletshield ; go build -trimpath -ldflags ${ldflags} && mv walletshield /$(net_name)/walletshield.$(distro)'

.PHONY: start-walletshield
run-walletshield: $(net_dir)/walletshield.$(distro) $(net_dir)/running.stamp
	$(docker) run -d --network=host $(opt_docker_args) $(mount_net_name) --name walletshield --rm katzenpost-$(distro)_base \
		/$(net_name)/walletshield.$(distro) -config /$(net_name)/client/client.toml -listen :7070 -log_level DEBUG

.PHONY: stop-walletshield
stop-walletshield:
	$(docker) stop walletshield

# start the testnet in the background with the local customizations
start: clone-katzenpost custom-genconfig $(docker_compose_yml) custom-binaries
	$(MAKE) -e -C $(katzenpost_dir)/docker $@

# pass through all other targets to katzenpost/docker/Makefile
%: clone-katzenpost
	@echo ">> Passing '$@' to $(katzenpost_dir)/docker/Makefile"
	$(MAKE) -e -C $(katzenpost_dir)/docker $@
