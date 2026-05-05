FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    capnproto \
    libcapnp-dev \
    libboost-dev \
    pkgconf \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

RUN cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build build -j$(nproc) \
    && cmake --install build

RUN mkdir -p /usr/local/lib && \
    ldd /usr/local/bin/sv2-tp | \
    awk '/=>/ && $3 ~ /^\// {print $3}' | \
    while read -r lib; do \
      target="/usr/local/lib/$(basename "$lib")"; \
      cp "$lib" "$target"; \
    done

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/sv2-tp /usr/local/bin/sv2-tp
COPY --from=build /usr/local/lib /usr/local/lib

RUN ldconfig /usr/local/lib

VOLUME ["/home/bitcoin/.bitcoin"]

ENTRYPOINT ["/usr/local/bin/sv2-tp"]
CMD []
