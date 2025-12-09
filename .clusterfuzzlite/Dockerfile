FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update && apt-get install -y \
  build-essential \
  cmake \
  git \
  ninja-build \
  pkgconf \
  python3 \
  zip \
  && rm -rf /var/lib/apt/lists/*

COPY . $SRC/sv2-tp
WORKDIR $SRC/sv2-tp
RUN rm -rf assets && \
  git clone --depth=1 https://github.com/sjors/sv2-tp-qa-assets assets && \
  rm -rf assets/.git
COPY .clusterfuzzlite/build.sh $SRC/
