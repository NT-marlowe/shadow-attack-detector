#!/bin/bash
#
set -e
set -u
set -x

# install auditd
sudo apt install auditd -y

# install systemtap
sudo apt install gcc systemtap -y
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C8CAB6595FDFF622 
codename=$(lsb_release -c | awk  '{print $2}')
sudo tee /etc/apt/sources.list.d/ddebs.list << EOF
deb http://ddebs.ubuntu.com/ ${codename}      main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-security main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-updates  main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
EOF

sudo apt-get update
sudo apt-get install linux-image-$(uname -r)-dbgsym

# install perf
sudo apt install linux-tools-common linux-tools-generic linux-tools-$(uname -r) -y

# install bpftrace
sudo apt install bpftrace -y
