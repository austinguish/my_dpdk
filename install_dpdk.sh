#!/usr/bin/bash
sudo chmod 770 /mydata
sudo apt update
sudo apt install cmake libnuma-dev -y
cd /mydata && {
    git clone https://github.com/DPDK/dpdk
    cd dpdk
    git checkout releases
    meson build -Dexamples=all -Dbuildtype=debug
    cd build && \
    meson configure -Dexamples=all -Dbuildtype=debug && \
    ninja && \
    sudo ninja install && \
    sudo ldconfig
}

echo 1024 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages