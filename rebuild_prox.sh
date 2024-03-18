#!/bin/bash
set -e
cd /opt/samplevnf/VNFs/DPPD-PROX/
git pull
export PKG_DEST="/opt"
export RTE_SDK="${PKG_DEST}/dpdk"
meson build
ninja -C build install
# make -j8
cd -

