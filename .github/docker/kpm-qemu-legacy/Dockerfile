# Image for the KPM harness's LEGACY (pre-GKI) targets: 4.14 / 4.19 / 5.4 —
# the kernels the .ko backend can't serve (no GKI, no DDK). Unlike ddk-qemu
# (per-KMI, DDK clang, kept kernel tree), this is ONE lightweight image:
#
#   debian + one Bootlin aarch64 gcc (fetched by build-source-kernel.sh)
#   + the 3 built virtio Images
#   + Alpine minirootfs + KernelPatch tool/runtime + clang (for `make kpm`)
#
# No DDK and no kernel tree: the .kpm is relocatable (built per-PR against the
# KernelPatch submodule), so nothing here is built against the kernel. Built
# rarely (qemu-image.yml) since these kernels are pinned.
#
# trixie (not bookworm): the prebuilt kptools-linux is linked against glibc
# >= 2.38; bookworm ships 2.36 and the dynamic loader rejects it. trixie = 2.41.

# --- builder: the bionic getifaddrs probe ----------------------------------
# The gai_getifaddrs vector must run a *bionic* binary (it validates how
# Android's getifaddrs parses our filtered netlink dump — glibc differs and is
# the wrong libc to test). Build it from gai-probe.c with the NDK here; only
# the ~420 KB static binary is copied into the final image (no NDK retained).
FROM debian:trixie-slim AS gai
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates unzip && rm -rf /var/lib/apt/lists/*
ARG NDK_VER=r28c
RUN curl -fsSL "https://dl.google.com/android/repository/android-ndk-${NDK_VER}-linux.zip" \
        -o /tmp/ndk.zip && \
    unzip -q /tmp/ndk.zip "android-ndk-${NDK_VER}/toolchains/llvm/prebuilt/linux-x86_64/*" \
        -d /opt && rm /tmp/ndk.zip
COPY kmod/test/gai-probe.c /tmp/gai-probe.c
COPY kmod/test/bind-probe.c /tmp/bind-probe.c
RUN TC="/opt/android-ndk-${NDK_VER}/toolchains/llvm/prebuilt/linux-x86_64/bin" && \
    "$TC/aarch64-linux-android24-clang" -static -O2 -o /opt/gai /tmp/gai-probe.c && \
    "$TC/aarch64-linux-android24-clang" -static -O2 -Wall -Wextra -Werror \
        -o /opt/bind-probe /tmp/bind-probe.c && \
    "$TC/llvm-strip" /opt/gai /opt/bind-probe

FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-system-arm cpio gzip xz-utils bzip2 curl ca-certificates git make \
        bc bison flex libelf-dev libssl-dev \
        gcc g++ libc6-dev \
        clang lld gcc-aarch64-linux-gnu && \
    rm -rf /var/lib/apt/lists/*

# Build the 3 legacy kernels (Bootlin gcc, pinned sources, qemu.config + SW PAN)
# and keep only the Images — drop the fetched sources + toolchain afterwards.
COPY kmod/test /src/kmod/test
RUN cd /src && \
    for v in 4.14 4.19 5.4; do \
        kmod/test/build-source-kernel.sh "$v" "/opt/qemu/legacy/$v"; \
    done && \
    rm -rf /src/kmod/test/.cache

# Alpine rootfs + pinned KernelPatch tool/runtime (same as ddk-qemu).
RUN curl -fsSL \
        https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/aarch64/alpine-minirootfs-3.21.2-aarch64.tar.gz \
        -o /opt/qemu/alpine-minirootfs.tar.gz
ARG KP_VER=0.13.1
RUN mkdir -p /opt/qemu/kp && \
    for a in kptools-linux kpimg-linux; do \
        curl -fsSL "https://github.com/bmax121/KernelPatch/releases/download/${KP_VER}/$a" \
            -o "/opt/qemu/kp/$a"; \
    done && chmod +x /opt/qemu/kp/kptools-linux

# Prebuilt bionic getifaddrs and raw-syscall socket bind probes. Old kernels
# normally deny the first bind natively; running the probe still guards that
# assumption and makes any future behavior change visible.
COPY --from=gai /opt/gai /opt/qemu/gai
COPY --from=gai /opt/bind-probe /opt/qemu/bind-probe

# run-kpm.sh reads these. The per-version Image lives at
# /opt/qemu/legacy/<ver>/Image — the CI job sets VPNHIDE_QEMU_IMAGE +
# VPNHIDE_QEMU_CPU=cortex-a57 per matrix entry.
ENV VPNHIDE_QEMU_ROOTFS=/opt/qemu/alpine-minirootfs.tar.gz
ENV VPNHIDE_KP_BIN=/opt/qemu/kp
ENV VPNHIDE_GAI_BIN=/opt/qemu/gai
ENV VPNHIDE_BIND_BIN=/opt/qemu/bind-probe
