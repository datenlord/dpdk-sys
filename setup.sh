#!/bin/bash

# run as root
mkdir -p /dev/hugepages
mountpoint -q /dev/hugepages || mount -t hugetlbfs nodev /dev/hugepages
echo 8 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
