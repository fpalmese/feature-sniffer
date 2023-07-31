#!/bin/bash
PATH=$PATH:/usr/bin/make
cd /home/pi/nexmon
source setup_env.sh && echo "succeeded" || echo "failed"
make && echo "make succeeded" || echo "make failed"
cd /home/pi/nexmon/patches/bcm43455c0/7_45_189/nexmon_csi
make install-firmware && echo "install firm succeeded" || echo "install firm failed"
cd /home/pi/nexmon/utilities/nexutil 
make && make install && echo "make install succeeded" || echo "make install failed"
