#ifndef _POSIX_C_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <math.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>


static struct mnl_socket *nl;

// Probability Density Function using Box-Muller transformation
double gaussian_distribution(double mean, double stddev) {
    static int have_spare = 0;
    static double spare;

    if (have_spare) {
        have_spare = 0;
        return mean + stddev * spare;
    }

    have_spare = 1;

    double u, v, s;
    // do-while to avoid division by zero
    do {
        u = (rand() / (double)RAND_MAX) * 2.0 - 1.0;
        v = (rand() / (double)RAND_MAX) * 2.0 - 1.0;
        s = u * u + v * v;
    } while (s >= 1.0 || s == 0.0);

    s = sqrt(-2.0 * log(s) / s);
    spare = v * s;
    return mean + stddev * u * s;
}

// Boolean which returns true if packet should be dropped.
bool should_drop_packet(uint32_t id) {
    double mean = 3.0;
    double stddev = 0.5;
    double drop_probability = gaussian_distribution(mean, stddev);
    return false; // drop_probability > 0.1;
}

// Apply delay to packet processing, NB: for each single packet.
double apply_delay_packet() {
    struct timespec delay, start_time, end_time;
    delay.tv_sec = 0;
    // Need to convert nanoseconds to milliseconds
    delay.tv_nsec = gaussian_distribution(60, 5) * pow(10, 6); // Cannot choose values over 1000ms, will not be added
    long int milliseconds_delay = delay.tv_nsec / pow (10,6);

    // The intended delay
    printf("Intended delay: %ld milliseconds\n", milliseconds_delay);

    // Get start time
    if (clock_gettime(CLOCK_MONOTONIC, &start_time) == -1) {
        perror("clock_gettime");
        return 0;
    }

    // Introduce delay (latency)
    if (nanosleep(&delay, NULL) != 0) {
        perror("nanosleep");
        // Continue execution even if nanosleep fails
    }

    // Get end time
    if (clock_gettime(CLOCK_MONOTONIC, &end_time) == -1) {
        perror("clock_gettime");
        return 0;
    }

    // Calculate actual delay
    double elapsed = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    printf("Actual delay: %.3f seconds\n", elapsed);
    return elapsed;
}

// The function which sends the verdict (accept, drop) back to netfilter.
void nfq_send_verdict(int queue_num, uint32_t id, int verdict) {

    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct nlattr *nest;
    verdict;

    // Prepare netlink message header
    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);

    // Set the verdig of the packet.
    nfq_nlmsg_verdict_put(nlh, id, verdict);

    // example to set the connmark. First, start NFQA_CT section:
    nest = mnl_attr_nest_start(nlh, NFQA_CT);

    // then, add the connmark attribute:
    mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));

    // end conntrack section
    mnl_attr_nest_end(nlh, nest);

    // Send the verdict message.
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }
}