#!/bin/bash
sudo ip link add  nlmon0 type nlmon
sudo ip link set dev nlmon0 up
touch netlink.pcap
wireshark -Y '!nl80211 && !netlink-route' -k -i <(tail -f -c +0 netlink.pcap) &
sleep 1
sudo tcpdump -i nlmon0 -w netlink.pcap
