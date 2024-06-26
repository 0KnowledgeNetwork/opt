.PHONY: clean clean-local clean-local-dryrun clean-image-% clean-container-% clean-images test rootshell shell run-ping go-mod-tidy go-mod-upgrade help start run stop

help:
	@echo "These make targets allow you to control the test network:"
	@echo " run                - run the testnet in the foreground, until ctrl-C"
	@echo " start              - start the testnet in the background"
	@echo " stop               - stop the testnet"
	@echo " wait               - wait for testnet to have consensus"
	@echo " watch              - tail -F all logs"
	@echo " status             - show testnet consensus status"
	@echo " show-latest-vote   - does what it says"
	@echo " run-ping           - send a ping over the testnet"
	@echo " run-walletshield   - run walletshield app with testnet"
	@echo " stop-walletshield  - stop running walletshield"
	@echo " clean-bin          - stop, and delete compiled binaries"
	@echo " clean-local        - stop, and delete data and binaries"
	@echo " clean-local-dryrun - show what clean-local would delete"
	@echo " clean              - the above, plus cleans includes go_deps images"
	@echo

warped?=true
mixes=3
auths=3
gateways=1
serviceNodes=1

# Parameters
sr=0
mu=0.005
muMax=1000
lP=0.001
lPMax=1000
lL=0.0005
lLMax=1000
lD=0.0005
lDMax=3000
lM=0.0005
lMMax=100
lGMax=1000

UserForwardPayloadLength=30000

# hybrid ctidh PQ can work here, but requires manually building ctidh.
nike=x25519

# kem can be Kyber1024-X448 or any of the other schemes at https://github.com/cloudflare/circl/blob/main/kem/schemes/schemes.go (and then nike must be unset)
kem=

DISTROS=alpine debian
distro=alpine
wirekem=xwing
net_name=voting_mixnet
base_port=30000
bind_addr=127.0.0.1
docker_compose_yml=$(net_name)/docker-compose.yml
sh=$(shell if echo ${distro}|grep -q alpine; then echo sh; else echo bash; fi)
SHELL=/bin/bash
cache_dir=cache

# log_level can be DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL
log_level=DEBUG

docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)

ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

uid?=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid?=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)

opt_workspace=/go/opt
katzenpost_workspace=/go/katzenpost
katzenpost_dir=./katzenpost
katzenpost_version=$(shell grep -E '^	github.com/katzenpost/katzenpost ' ../go.mod | awk '{print $$2}')

docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker_args=--user ${docker_user} --volume $(shell readlink -f $(katzenpost_dir)):$(katzenpost_workspace) --workdir $(katzenpost_workspace) -v $(shell readlink -f .)/$(cache_dir)/go:/go/ -v $(shell readlink -f .)/$(cache_dir)/root_cache:/root/.cache

opt_docker_args=--user ${docker_user} --volume $(shell readlink -f ..):$(opt_workspace) --workdir $(opt_workspace)

replace_name=$(shell if echo ${docker}|grep -q podman; then echo " --replace --name"; else echo " --name"; fi)
i_if_podman=$(shell if echo ${docker}|grep -q podman; then echo " -i"; else echo; fi)
mount_net_name=-v `pwd`/$(net_name):/$(net_name)

docker_compose_v1_or_v2?= $(shell [ -e /usr/libexec/docker/cli-plugins/docker-compose ] && echo /usr/libexec/docker/cli-plugins/docker-compose || echo docker-compose)
docker_compose?= $(shell if which podman|grep -q .; then echo DOCKER_HOST="unix://$$XDG_RUNTIME_DIR/podman/podman.sock" $(docker_compose_v1_or_v2); else echo $(docker_compose_v1_or_v2); fi)

make_args=--no-print-directory net_name=$(net_name) docker=$(docker) distro=$(distro) warped=$(warped) docker_user=$(docker_user)

$(net_name):
	mkdir -vp $(net_name)

$(cache_dir): $(cache_dir)/go $(cache_dir)/root_cache

$(cache_dir)/go:
	mkdir -vp $(cache_dir)/go

$(cache_dir)/root_cache:
	mkdir -vp $(cache_dir)/root_cache

clone-katzenpost:
	if [ ! -d "$(katzenpost_dir)" ]; then \
		git clone \
			--branch $(katzenpost_version) \
			--depth 1 \
			--single-branch \
			https://github.com/katzenpost/katzenpost.git \
			$(katzenpost_dir); \
	fi

$(docker_compose_yml): ../genconfig/main.go $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run ${opt_docker_args} --rm katzenpost-$(distro)_base \
		$(sh) -c 'cd genconfig && go build && cd ../docker \
		&& ../genconfig/genconfig -wirekem $(wirekem) -a ${bind_addr} -nv ${auths} -n ${mixes} -gateways ${gateways} \
		-serviceNodes ${serviceNodes} \
		-sr ${sr} -mu ${mu} -muMax ${muMax} -lP ${lP} -lPMax ${lPMax} -lL ${lL} \
		-lLMax ${lLMax} -lD ${lD} -lDMax ${lDMax} -lM ${lM} -lMMax ${lMMax} \
		-S .$(distro) -v -o ./$(net_name) -b /$(net_name) -P $(base_port) \
		-nike "$(nike)" -kem "$(kem)" -d katzenpost-$(distro)_base \
		-UserForwardPayloadLength $(UserForwardPayloadLength) -log_level $(log_level)'

$(net_name)/running.stamp:
	make $(make_args) start

run: $(docker_compose_yml) $(net_name)/server.$(distro) $(net_name)/voting.$(distro)
	cd $(net_name) && touch running.stamp \
	&& DOCKER_USER=${docker_user} $(docker_compose) up --remove-orphans
	cd $(net_name) && rm -v running.stamp

start: clone-katzenpost $(docker_compose_yml) $(net_name)/http_proxy.$(distro) $(net_name)/server.$(distro) $(net_name)/voting.$(distro) 
	cd $(net_name); DOCKER_USER=${docker_user} $(docker_compose) up --remove-orphans -d; $(docker_compose) top
	touch $(net_name)/running.stamp

stop:
	[ -e $(net_name) ] && cd $(net_name) && $(docker_compose) down --remove-orphans; rm -fv running.stamp

watch:
	tail -F $(net_name)/*/*.log

status:
	@[ -d $(net_name) ] || (echo "./$(net_name)/ does not exist" && false)
	tail -10 $(net_name)/auth1/katzenpost.log
	@echo
	@du -hs ./$(net_name)
	@echo "Current time: $$(TZ=UTC date "+%H:%M:%S %Z") (compare to log timestamps to see if they are current)"
	@cat $(net_name)/auth1/katzenpost.log |grep Genesis|tail -1|while read a b c d; do \
			echo "Network appears to have been running for $$(($$b - $$d)) consecutive epochs:"; \
			grep 'Consensus made' $(net_name)/auth1/katzenpost.log; \
		done|grep . || (echo "(no consensus yet; exiting with error)" && false)

show-latest-vote:
	@grep -A30 'Ready to send' voting_mixnet/auth1/katzenpost.log |tail -30|sed /Sending/q

wait: $(net_name)/running.stamp | $(cache_dir)
	$(docker) run --network=host ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
	/$(net_name)/fetch.$(distro) -f /$(net_name)/client/client.toml

debian_base.stamp:
	$(docker) run $(replace_name) katzenpost_debian_base docker.io/golang:bullseye $(sh) -c "echo -e 'deb https://deb.debian.org/debian bullseye main\ndeb https://deb.debian.org/debian bullseye-updates main\ndeb https://deb.debian.org/debian-security bullseye-security main' > /etc/apt/sources.list && cat /etc/apt/sources.list && apt update && apt upgrade -y && apt install -y pv && adduser katzenpost --gecos '' --disabled-password && apt update && apt upgrade -y"
	$(docker) commit katzenpost_debian_base katzenpost-debian_base
	$(docker) rm katzenpost_debian_base
	touch $@

alpine_base.stamp:
	$(docker) run $(replace_name) katzenpost_alpine_base docker.io/golang:alpine sh -c 'adduser katzenpost --gecos "" --disabled-password  && apk update && apk upgrade && apk add gcc musl-dev make pv' \
	&& $(docker) commit katzenpost_alpine_base katzenpost-alpine_base \
	&& $(docker) rm katzenpost_alpine_base
	touch $@

go-mod-tidy: $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run ${docker_args} katzenpost-$(distro)_base \
			$(sh) -c "go mod tidy"

go-mod-upgrade: $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run ${docker_args} katzenpost-$(distro)_base \
			$(sh) -c 'go get -d -u ./... && go mod tidy'

$(net_name)/server.$(distro): $(distro)_base.stamp $(docker_compose_yml) | $(net_name) $(cache_dir)
		$(docker) run ${docker_args} $(mount_net_name) --rm katzenpost-$(distro)_base \
			$(sh) -c 'cd server && make $(make_args) testnet-build testnet-install'

$(net_name)/voting.$(distro): $(distro)_base.stamp $(docker_compose_yml) | $(net_name) $(cache_dir)
		$(docker) run ${docker_args} $(mount_net_name) --rm katzenpost-$(distro)_base \
			$(sh) -c 'cd authority && make $(make_args) cmd/voting/voting cmd/fetch/fetch && \
			mv cmd/voting/voting /$(net_name)/voting.$(distro) && \
			mv cmd/fetch/fetch /$(net_name)/fetch.$(distro)'

$(net_name)/ping.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker) run ${docker_args} $(mount_net_name) --rm katzenpost-$(distro)_base \
			$(sh) -c 'cd ping && go mod verify && go build -ldflags ${ldflags} && \
			mv ping /$(net_name)/ping.$(distro)'

$(net_name)/http_proxy.$(distro): $(distro)_base.stamp | $(net_name) $(cache_dir)
		$(docker) run $(opt_docker_args) $(mount_net_name) katzenpost-$(distro)_base \
			$(sh) -c 'cd $(opt_workspace)/server_plugins/cbor_plugins/http_proxy/cmd/http_proxy && go mod verify && go build -ldflags ${ldflags} && \
			mv http_proxy /$(net_name)/http_proxy.$(distro)'
		cp ../server_plugins/cbor_plugins/http_proxy/http_proxy_config.toml ./$(net_name)/servicenode1/

clean-images: stop
	@-for distro in $(DISTROS); do \
		make $(make_args) distro=$$distro clean-container-$${distro}_base; \
		make $(make_args) distro=$$distro clean-image-$${distro}_base; \
	done \

clean-container-%:
	-@$(docker) stop $(i_if_podman) $(patsubst clean-container-%,katzenpost_%,$@)
	-@$(docker) rm   $(i_if_podman) $(patsubst clean-container-%,katzenpost_%,$@)

clean-image-%:
	-$(docker) rmi $(patsubst clean-image-%,katzenpost-%,$@)
	-rm -fv $(patsubst clean-image-%,%,$@).stamp

clean-bin: stop
	rm -vf ./$(net_name)/*.$(distro)

clean-local: clean-bin
	git clean -f -x $(net_name)
	git status .

clean-local-dryrun:
	git clean -n -x $(net_name)

clean: clean-images clean-local
	rm -rfv $(cache_dir)
	-$(docker) ps -a|grep katzenpost|cat
	-$(docker) images|grep katzenpost|cat
	rm -rf $(katzenpost_dir)

$(net_name)/walletshield.$(distro): $(distro)_base.stamp $(net_name)/http_proxy.$(distro) | $(net_name) $(cache_dir)
		$(docker) run $(opt_docker_args) $(mount_net_name) katzenpost-$(distro)_base \
			$(sh) -c 'cd $(opt_workspace)/apps/walletshield && go mod verify && go build -ldflags ${ldflags} && \
			mv walletshield /$(net_name)/walletshield.$(distro)'

run-walletshield: $(net_name)/walletshield.$(distro) $(net_name)/running.stamp | $(cache_dir)
		$(docker) run -d --network=host $(opt_docker_args) $(mount_net_name) --name walletshield  --rm katzenpost-$(distro)_base \
        /$(net_name)/walletshield.$(distro) -config /$(net_name)/client/client.toml -listen :7070 -log_level DEBUG

stop-walletshield:
		$(docker) stop walletshield

run-ping: $(net_name)/ping.$(distro) $(net_name)/running.stamp | $(cache_dir)
	$(docker) run --network=host ${docker_args} $(mount_net_name) --rm  katzenpost-$(distro)_base \
        /$(net_name)/ping.$(distro) -c /$(net_name)/client/client.toml -s echo -printDiff -n 1

shell: $(distro)_base.stamp | $(net_name) $(cache_dir)
	$(docker) run --network=host ${docker_args} $(mount_net_name) -w /$(net_name) --rm -it katzenpost-$(distro)_base $(sh)

# this is for running with docker, where we are root outside and (except for
# here) non-root inside. When using podman, we are rootless outside and uid 0
# inside already, so this target is never needed.
rootshell: $(distro)_base.stamp
	$(docker) run --network=host --user 0:0 -v $(shell readlink -f ..):/go/katzenpost --rm -it katzenpost-$(distro)_base $(sh)

test: wait
	cd ../client    && make $(make_args) testargs=$(testargs) dockerdockertest
	cd ../catshadow && make $(make_args) testargs=$(testargs) dockerdockertest
	cd ../memspool  && make $(make_args) testargs=$(testargs) dockerdockertest

check-go-version:
	podman run --rm katzenpost-alpine_base go version
