## Network Emulator
A working implementation of a Network Emulator based on libnetfilter_queue (https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html).

The goal of the implementation is to provide a more flexible approach when it comes to manipulating traffic over a network compared to established tools such as NetEm and Linux Traffic Control.

The implementation allows the user to add latency and packet loss, as well as other metrics in order to simulate how the network performs under changing conditions. The motivation behind the implementation is to run the script on a machine with two network interfaces, acting as a switch for the traffic sent from devices to the network. This is achieved by using NFQUEUE, which places all packets in a queue where latency and other things can be applied. By doing this, we are able to manipulate the stream of packets inbetween the devices on the network.

To achieve random behaviour, a version of the psuedo-random number generator Mersenne Twister (https://dl.acm.org/doi/pdf/10.1145/272991.272995) has been added.

## Setup
The implementation requires a Linux device, as libnetfilter_queue is not supported on other devices. Furthermore, we need to configure iptables rules on the forwarding machine. The following ruleset is applied:
- sudo iptables -A FORWARD -p udp —sport 4200 -j NFQUEUE —queue-num 0
- sudo iptables -A FORWARD -p udp —dport 4200 -j NFQUEUE —queue-num 0

This ruleset forwards the udp traffic from/to port 4200 to the NFQUEUE number 0. This ruleset can be adjusted based on the desired functionality of the emulator.

On the machine generating the traffic, apply the following iproutes:
- sudo ip route add default via x.x.x.x

Replace the address with the address of your forwarding machine. If the default route is not defined, the traffic may be routed differently and is sent directly to the gateway. The result is no packets admitted to the queue where the manipulation is done.

## Build
The program can be built either by CMake or gcc. When testing, gcc has been used. Use the following commands:

- gcc -o nf-queue nf-queue.c -lnetfilter_queue -lmnl -lm
- sudo ./nf-queue 0

It is important to notice that the queue number needs to be specified when building the executable.
