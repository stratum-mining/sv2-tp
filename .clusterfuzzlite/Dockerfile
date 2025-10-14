FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
  build-essential \
  cmake \
  pkgconf \
  python3 \
  libcapnp-dev \
  capnproto \
  zip \
  && rm -rf /var/lib/apt/lists/*

COPY . $SRC/sv2-tp
WORKDIR $SRC/sv2-tp
RUN rm -rf assets && \
  git clone --depth=1 https://github.com/sjors/sv2-tp-qa-assets assets && \
  rm -rf assets/.git
COPY .clusterfuzzlite/build.sh $SRC/
