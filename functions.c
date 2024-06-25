#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
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

// Implementation using Box-Muller transformation
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
        u = (rand() / (double)RAND_MAX) * 2.0 - 1.0;
        s = u * u + v * v;
    } while (s >= 1.0 || s == 0.0);

    s = sqrt(-2.0 * log(s) / s);
    spare = v * s;
    return mean + stddev * u * s;
}

bool drop_packet_parameter(uint32_t id) {
        double drop_probability = gaussian_distribution(0.5, 0.2);
        if (drop_probability > 0.5) {
            return true;
        } else {
            return false;
        }
}

void apply_delay_packet() {
    struct timespec delay, start_time, end_time;
    /* int list_delay[] = {1, 2, 3, 4, 5};
    int index_random = rand() % (sizeof(list_delay) / sizeof(list_delay[0]));
    delay.tv_sec = list_delay[index_random]; */
    delay.tv_sec = gaussian_distribution(3, 0.5);
    delay.tv_nsec = 0;
    
    printf("Intended delay: %ld seconds\n", delay.tv_sec);

    // Get start time
    if (clock_gettime(CLOCK_MONOTONIC, &start_time) == -1) {
        perror("clock_gettime");
        return;
    }

    // Introduce delay (latency)
    if (nanosleep(&delay, NULL) != 0) {
        perror("nanosleep");
        // Continue execution even if nanosleep fails
    }

    // Get end time
    if (clock_gettime(CLOCK_MONOTONIC, &end_time) == -1) {
        perror("clock_gettime");
        return;
    }

    // Calculate actual delay
    double elapsed = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    printf("Actual delay: %.6f seconds\n", elapsed);
}

void nfq_send_verdict(int queue_num, uint32_t id, int verdict) {

        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh;
        struct nlattr *nest;

        nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);

        nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);
        /* example to set the connmark. First, start NFQA_CT section: */
        nest = mnl_attr_nest_start(nlh, NFQA_CT);

        /* then, add the connmark attribute: */
        mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
        /* more conntrack attributes, e.g. CTA_LABELS could be set here */

        /* end conntrack section */
        mnl_attr_nest_end(nlh, nest);

        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
        {
                perror("mnl_socket_send");
                exit(EXIT_FAILURE);
        }
}