#!/bin/sh

sudo ifconfig tun0 inet 10.0.0.2 10.0.0.1 up
sudo route add 192.168.2.0/24 -interface tun0
