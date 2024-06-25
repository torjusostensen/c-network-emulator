#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>

static struct mnl_socket *nl;

static void nfq_send_verdict(int queue_num, uint32_t id, int verdict) {

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

        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
                perror("mnl_socket_send");
                exit(EXIT_FAILURE);
        }
}

static int queue_cb(const struct nlmsghdr *nlh, void *data) {
    struct nfqnl_msg_packet_hdr *ph = NULL;
    struct nlattr *attr[NFQA_MAX+1] = {};
    uint32_t id = 0, skbinfo;
    struct nfgenmsg *nfg;
    uint16_t plen;

    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    nfg = mnl_nlmsg_get_payload(nlh);

    if (attr[NFQA_PACKET_HDR] == NULL) {
        fputs("metaheader not set\n", stderr);
        return MNL_CB_ERROR;
    }

    ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);

    skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    id = ntohl(ph->packet_id);
    printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u)",
           id, ntohs(ph->hw_protocol), ph->hook, plen);

    if (skbinfo & NFQA_SKB_CSUMNOTREADY)
        printf(", checksum not ready");
    puts("");

    // Check if the ID is even (including 0)
    if (id % 2 == 0) {
        printf("Dropping packet, id is even: %u\n", id);
        nfq_send_verdict(ntohs(nfg->res_id), id, NF_DROP);
        return MNL_CB_OK;  // Return immediately after dropping
    }

    // Only proceed with delay logic for odd IDs
    struct timespec delay;
    int list_delay[] = {1, 2, 3, 4, 5};
    int index_random = rand() % (sizeof(list_delay) / sizeof(list_delay[0]));
    delay.tv_sec = list_delay[index_random];
    delay.tv_nsec = 0;
    printf("Delay: %ld seconds\n", delay.tv_sec);

    // Print timestamp before delay
    struct timespec start_time;
    if (clock_gettime(CLOCK_MONOTONIC, &start_time) == -1) {
        perror("clock_gettime");
        return MNL_CB_ERROR;
    }
    printf("Before delay: %ld seconds\n", start_time.tv_sec);

    // Introduce delay (latency)
    if (nanosleep(&delay, NULL) != 0) {
        perror("nanosleep");
        // Continue execution even if nanosleep fails
    }

    // Print timestamp after delay
    struct timespec end_time;
    if (clock_gettime(CLOCK_MONOTONIC, &end_time) == -1) {
        perror("clock_gettime");
        return MNL_CB_ERROR;
    }
    printf("After delay: %ld seconds\n", end_time.tv_sec);

    // Accept the packet if ID is odd
    nfq_send_verdict(ntohs(nfg->res_id), id, NF_ACCEPT);

    return MNL_CB_OK;
}

int main(int argc, char *argv[]) {
        
        char *buf;
        /* largest possible packet payload, plus netlink data overhead: */
        size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
        struct nlmsghdr *nlh;
        int ret;
        unsigned int portid, queue_num;

        if (argc != 2) {
                printf("Usage: %s [queue_num]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
        queue_num = atoi(argv[1]);

        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (nl == NULL) {
                perror("mnl_socket_open");
                exit(EXIT_FAILURE);
        }

        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
                perror("mnl_socket_bind");
                exit(EXIT_FAILURE);
        }
        portid = mnl_socket_get_portid(nl);

        buf = malloc(sizeof_buf);
        if (!buf) {
                perror("allocate receive buffer");
                exit(EXIT_FAILURE);
        }

        nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
        nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
                perror("mnl_socket_send");
                exit(EXIT_FAILURE);
        }

        nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
        nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

        mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
        mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
                perror("mnl_socket_send");
                exit(EXIT_FAILURE);
        }

        /* ENOBUFS is signalled to userspace when packets were lost
         * on kernel side.  In most cases, userspace isn't interested
         * in this information, so turn it off.
         */
        ret = 1;
        mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

        for (;;) {
                ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
                if (ret == -1) {
                        perror("mnl_socket_recvfrom");
                        exit(EXIT_FAILURE);
                }

                ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
                if (ret < 0) {
                        perror("mnl_cb_run");
                        exit(EXIT_FAILURE);
                }
        }

        mnl_socket_close(nl);

        return 0;
}