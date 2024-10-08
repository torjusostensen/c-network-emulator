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

// Apply delay to packet processing, NB: for each single packet.
double apply_delay_packet() {
    struct timespec delay, start_time, end_time;
    delay.tv_sec = 0;
    delay.tv_nsec = 0;

    // Applying distribution in milliseconds, messy to write it as nanoseconds
    double distribution_milliseconds = 150; //gaussian_distribution(50, 0);
    delay.tv_nsec = (long)(distribution_milliseconds * 1e6);
    
    // If ms > 1000, then error. Converting to seconds if large enough value.
    if (delay.tv_nsec >= 1e9) {
        delay.tv_sec += delay.tv_nsec / 1e9;
        delay.tv_nsec = delay.tv_nsec & (long) 1e9;
    }

    long int milliseconds_delay = delay.tv_nsec / (long) 1e6;

    printf("Intended delay: %ld seconds and %ld milliseconds\n", delay.tv_sec, milliseconds_delay);

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
    printf("\n");
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