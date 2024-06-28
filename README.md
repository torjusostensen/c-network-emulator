# Libnetfilter_queue Implementation

A working implementation of libnetfilter_queue (https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html) made in the context of a project in Domos.

The background is the network quality framework Quality of Outcome (https://datatracker.ietf.org/doc/draft-ietf-ippm-qoo), and the goal of the implementation is to manipulate the traffic over a network to a greater extent than established tools such as NetEm and Linux Traffic Control.

The implementation allows the user to add latency, packet loss and other metrics to simulate how the network conditions evolve. The idea is to run the program on a computer with both an input and output interface, to be able to manipulate the stream of packets inbetween the devices on the network.

## Configuration
On the forwarding machine (the machine in the middle), apply the following iptables ruleset:
- sudo iptables -A FORWARD -p udp —sport 4200 -j NFQUEUE —queue-num 0
- sudo iptables -A FORWARD -p udp —dport 4200 -j NFQUEUE —queue-num 0

This ruleset forwards all udp traffic from/to port 4200 to NFQUEUE and more specifically queue number 0. Important to notice that port 4200 is specific to the server used, and needs to be changed if another twamp-server with different port number is used.

On the machine running twamp, apply the following:
- Sudo ip route add default via 192.168.32.116

By doing this, we make sure that the traffic is forwarded through the forwarding machine. If it is not defined, then the traffic is routed differently directly to the gateway and no packets are admitted to NFQUEUE.

## Build
The program can be built either by CMake or gcc. When testing, gcc has been used. The following commands is used:

- gcc -o nf-queue nf-queue.c -lnetfilter_queue -lmnl -lm
- sudo ./nf-queue 0

It is important to notice that the queue number needs to be specified when building the executable.
