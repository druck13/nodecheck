#!/bin/bash
mkdir -p /mnt/n1/share1/test
mount -t nfs 192.168.0.1:/mnt/share1/test /mnt/n1/share1/test

mkdir -p /mnt/n2/share1/test
mount -t nfs 192.168.0.2:/mnt/share1/test /mnt/n1/share1/test

nodecheck.py /mnt/n1/share1/test /mnt/n1/share1/test $@
