# ConfLabelReader + IReflx with iptables watchdog.
#
# Build straight from GitHub (no checkout needed):
#   docker build -t conflabelreader https://github.com/rainisto/ConfLabelReader.git#iptables-2026
# or from a local checkout of this branch:
#   docker build -t conflabelreader .
# Run:
#   docker run --cap-add NET_ADMIN -p 50000:50000/udp conflabelreader
#
# ConfLabelReader is built from the build context (this repository).
# The other dependencies come from the rainisto forks, branch iptables-2026
# (exip = upstream; mp2tp pinned before the "Use stdint" change that
# ConfLabelReader does not build against yet; IReflx + iptables patch).

FROM ubuntu:noble AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git cmake build-essential pkg-config \
      libboost-program-options-dev libboost-url-dev libbrotli-dev \
    && rm -rf /var/lib/apt/lists/*

ARG REPO=https://github.com/rainisto
ARG BRANCH=iptables-2026
WORKDIR /src
RUN for r in exip mp2tp IReflx; do \
      git clone --depth 1 --branch "$BRANCH" "$REPO/$r.git" "$r" || exit 1; \
    done

RUN cmake -S exip  -B exip/build  -DCMAKE_BUILD_TYPE=Release && cmake --build exip/build  -j && cmake --install exip/build
RUN cmake -S mp2tp -B mp2tp/build -DCMAKE_BUILD_TYPE=Release && cmake --build mp2tp/build -j && cmake --install mp2tp/build
RUN cmake -S IReflx -B IReflx/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build IReflx/build -j && cmake --install IReflx/build

# Upstream gets brotli from vcpkg (target unofficial::brotli::brotlidec);
# Ubuntu's libbrotli-dev ships only pkg-config files, so provide that target.
RUN mkdir -p /usr/local/lib/cmake/unofficial-brotli && printf '%s\n' \
      'if(NOT TARGET unofficial::brotli::brotlidec)' \
      '  find_package(PkgConfig REQUIRED)' \
      '  pkg_check_modules(BROTLIDEC REQUIRED IMPORTED_TARGET libbrotlidec)' \
      '  add_library(unofficial::brotli::brotlidec INTERFACE IMPORTED)' \
      '  target_link_libraries(unofficial::brotli::brotlidec INTERFACE PkgConfig::BROTLIDEC)' \
      'endif()' > /usr/local/lib/cmake/unofficial-brotli/unofficial-brotli-config.cmake

COPY . ConfLabelReader
RUN cmake -S ConfLabelReader -B ConfLabelReader/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build ConfLabelReader/build -j && cmake --install ConfLabelReader/build


FROM ubuntu:noble
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      iptables libbrotli1 tstools nano \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/ConfLabelReader /usr/local/bin/IReflxApp /usr/local/bin/
COPY --from=build /usr/local/lib/libLabelDemux.so* /usr/local/lib/
RUN ldconfig

EXPOSE 50000/udp

# Needs: docker run --cap-add NET_ADMIN ...
# Optional label filter: append e.g. -r'<regex>' to ConfLabelReader.
# Watchdog timeout: -w<ms> (default 3000; use 2.5-3x the label interval).
CMD /usr/local/bin/IReflxApp -s0.0.0.0:50000 | /usr/local/bin/ConfLabelReader
