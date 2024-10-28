# Docker Test Network

The Makefile and scripts here allow developers of 0KN mix network apps and server-side plugins to
locally run an offline Katzenpost test network with a podman-compatible docker-compose
configuration. It is meant for developing and testing client and server mix network components as
part of the core developer work flow.

This Makefile covers 0KN-specifics and proxies other targets to Katzenpost's `docker/Makefile`.
Refer to [Katzenpost Docker test network](https://github.com/katzenpost/katzenpost/tree/main/docker)
for more info.
