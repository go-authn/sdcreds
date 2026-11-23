# Interop image: Go toolchain + the REAL systemd-creds built from the v262.2 tag.
# Used to generate the committed vectors (internal/genvectors) and to run the
# interop tests in both directions in CI. No systemd package is installed: the
# binary under test is the one built here from the tag.
FROM golang:1.27.4 AS base

ARG SYSTEMD_TAG=v262.2
# The commit the tag must resolve to: a moved or re-created tag fails the build.
ARG SYSTEMD_COMMIT=63511d7283d7d0e2a2fc28075481afaf1a7be8f5
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates build-essential meson ninja-build gperf pkg-config \
        python3-jinja2 libcap-dev libmount-dev libssl-dev libcrypt-dev \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${SYSTEMD_TAG}" https://github.com/systemd/systemd /src/systemd \
    && test "$(git -C /src/systemd rev-parse HEAD)" = "${SYSTEMD_COMMIT}"
WORKDIR /src/systemd
RUN meson setup build -Dauto_features=disabled -Dopenssl=enabled -Dmode=release \
        -Dtests=false -Dlibmount=enabled -Dlibcrypt=enabled \
    && ninja -C build systemd-creds \
    && install -m 0755 build/systemd-creds /usr/local/bin/systemd-creds \
    && cp -a build/src/shared/libsystemd-shared-*.so /usr/local/lib/ 2>/dev/null; \
       ldconfig; systemd-creds --version

# Fixture user for the scoped (--uid) vectors.
RUN useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin sdcreds-test
WORKDIR /src/sdcreds
