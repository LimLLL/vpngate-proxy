# syntax=docker/dockerfile:1
# Builds the gateway with the pinned OpenVPN 3 Core on the same Ubuntu release
# CI tests against, then copies the binary and the bridge library into a slim
# runtime image.
ARG GO_VERSION=1.25

FROM golang:${GO_VERSION} AS go

FROM ubuntu:24.04 AS build
ARG OPENVPN3_COMMIT=0b27d9df493db8bc9dc459a2b1cb6b67037742b2
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates cmake g++ git ninja-build pkg-config \
        libasio-dev libcap-dev libfmt-dev libjsoncpp-dev liblz4-dev libssl-dev libxxhash-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git init -q /src/openvpn3 \
    && git -C /src/openvpn3 fetch -q --depth 1 https://github.com/OpenVPN/openvpn3.git "${OPENVPN3_COMMIT}" \
    && git -C /src/openvpn3 checkout -q --detach FETCH_HEAD
# The bridge only depends on these three files, so Go-only changes reuse it.
COPY go_backend/CMakeLists.txt go_backend/bridge.cpp go_backend/bridge.h /src/go_backend/
RUN cmake -S /src/go_backend -B /build/bridge -GNinja -DCMAKE_BUILD_TYPE=Release \
        -DOPENVPN3_SOURCE_DIR=/src/openvpn3 \
    && cmake --build /build/bridge
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local
COPY go_backend /src/go_backend
WORKDIR /src/go_backend
RUN CGO_ENABLED=1 CGO_LDFLAGS="-L/build/bridge -Wl,-rpath,/usr/local/lib" \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/vpngate-proxy ./cmd/vpngate-proxy

FROM ubuntu:24.04
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates iproute2 procps \
        libcap2 libfmt9 libjsoncpp25 liblz4-1 libssl3t64 libxxhash0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/bridge/libvpngate_bridge.so /usr/local/lib/
COPY --from=build /out/vpngate-proxy /usr/local/bin/
# Fail the build, not the first start, if a runtime library is missing or the
# binary cannot start on this architecture (--print-credentials needs no TUN).
RUN ldconfig && ! ldd /usr/local/bin/vpngate-proxy /usr/local/lib/libvpngate_bridge.so | grep -F "not found" \
    && vpngate-proxy --data-dir /tmp/smoke --print-credentials > /dev/null \
    && rm -rf /tmp/smoke
ENV VPNGATE_DATA_DIR=/data LOCAL_PROXY_HOST=0.0.0.0
VOLUME ["/data"]
EXPOSE 7928/tcp
ENTRYPOINT ["vpngate-proxy"]
