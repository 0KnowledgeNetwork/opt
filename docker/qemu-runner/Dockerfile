FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
  qemu-user-static \
  binfmt-support \
  libc6-arm64-cross \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# match expectations for lib locations
RUN ln -s /usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 /lib/ \
  && ln -s /usr/aarch64-linux-gnu/lib/ /lib/aarch64-linux-gnu

WORKDIR /app

# ENV QEMU_STRACE=1

ENTRYPOINT ["qemu-aarch64-static"]
