FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
  build-essential \
  cmake \
  git \
  ninja-build \
  pkgconf \
  python3 \
  libcapnp-dev \
  capnproto \
  zip \
  && rm -rf /var/lib/apt/lists/*

COPY . $SRC/sv2-tp
WORKDIR $SRC/sv2-tp
RUN mkdir -p /cxx_build \
  && if [ -d "$SRC/sv2-tp/cxx_build" ]; then cp -a "$SRC/sv2-tp/cxx_build/." /cxx_build/; fi
ENV CFL_TOOLCHAIN_STAMP_DIR=/cxx_build
RUN rm -rf assets && \
  git clone --depth=1 https://github.com/sjors/sv2-tp-qa-assets assets && \
  rm -rf assets/.git
COPY .clusterfuzzlite/build.sh $SRC/
