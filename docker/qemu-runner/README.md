# QEMU Runner Docker Image

This Docker image provides an environment for running binaries on `x64` built
for `linux-arm64` using QEMU user-mode emulation. The image could be extended
for other architectures.

## Build the Image

```bash
docker build -t zkn/qemu-runner:latest .
```

## Example Usage

### Start a Container with Bash

Run the container interactively with a mounted directory:

```bash
docker run --rm -ti -v "$(pwd)/ws:/app" --entrypoint bash zkn/qemu-runner:latest
```

### Run Binary `walletshield-linux-arm64`

Prepare a directory (`./ws/` for example) containing the necessary files:

1. The `walletshield-linux-arm64` binary.
2. A network deployment client configuration file (e.g., `client.toml`).

Run the binary inside the container:

```bash
# display help
docker run --rm -ti -v "$(pwd)/ws:/app" zkn/qemu-runner:latest /app/walletshield-linux-arm64 --help

# listen for RPC requests using the network client configuration:
docker run --rm -ti -v "$(pwd)/ws:/app" zkn/qemu-runner:latest /app/walletshield-linux-arm64 -config /app/client.toml -listen :7070
```

Notes:

- Ensure the binary has execute permissions.
- Ensure the binaries and configuration files are placed in the `ws` directory for mounting into the container.

## Using `QEMU_STRACE` for Debugging

The `QEMU_STRACE` environment variable enables detailed tracing of system calls
made by the emulated binary. This is useful for debugging issues with the
emulation such as missing dynamic libraries or incorrect paths.

### Enable QEMU_STRACE

To enable tracing, set the `QEMU_STRACE` environment variable using the `-e` option when running the container:

```bash
docker run --rm -ti -v "$(pwd)/ws:/app" -e QEMU_STRACE=1 zkn/qemu-runner:latest /app/walletshield-linux-arm64 --help
```
