[![Build Status](https://travis-ci.org/nttlman23/dhcpclient.svg?branch=master)](https://travis-ci.org/nttlman23/dhcpclient)

DHCPCLIENT

Based on https://github.com/JohannesBuchner/DHCProbe and https://github.com/samueldotj/dhcp-client

USAGE
./dhcpclient [-c ciaddr] [-g giaddr] [-r reqip] [-s server] [-l loglevel] [-v] -d devname
    -d - network interface
    -c - client ip address
    -g - gateway ip address
    -r - requested ip address
    -s - server ip address
    -l - log level (0 - quiet, 3 - verbose)
    -v - verbose (log level = 3)

BUILD
mkdir build && cd build
cmake ../
make

RUN
dhcpclient -d eth0
