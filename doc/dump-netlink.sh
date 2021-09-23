#!/bin/bash
sudo ip link add  nlmon0 type nlmon
sudo ip link set dev nlmon0 up
sudo rm netlink.pcap
touch netlink.pcap
wireshark -Y '!nl80211 && !netlink-route' -k -i <(tail -f -c +0 netlink.pcap) &
sudo tcpdump -i nlmon0 -w netlink.pcap
