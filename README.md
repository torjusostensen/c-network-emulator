A working implementation of libnetfilter_queue (https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html) made in the context of a project in Domos.

The background is the network quality framework Quality of Outcome (https://datatracker.ietf.org/doc/draft-ietf-ippm-qoo), and the goal of the implementation is to manipulate the traffic over a network to a greater extent than established tools such as NetEm and Linux Traffic Control.

The implementation allows the user to add latency, packet loss and other metrics to simulate how the network conditions evolve. The idea is to run the program on a computer with both an input and output interface, to be able to manipulate the stream of packets inbetween the devices on the network.






