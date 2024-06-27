#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <inttypes.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>
#include "nf-functions.c"

struct twamp_test_packet {
        uint32_t sequence_number;
        uint64_t timestamp;
        uint16_t error_estimate;
        uint16_t mbz1;
        uint64_t receive_timestamp;
        uint32_t sender_sequence_number;
        uint64_t sender_timestamp;
        uint16_t sender_error_estimate;
        uint16_t mbz2;
        uint8_t sender_ttl;
        uint8_t pad[7];
};

static struct mnl_socket *nl;

static int queue_cb(const struct nlmsghdr *nlh, void *data) {
        struct nfqnl_msg_packet_hdr *ph = NULL;
        struct nlattr *attr[NFQA_MAX + 1] = {};
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

        void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
        skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

        id = ntohl(ph->packet_id);
        printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u)", id, ntohs(ph->hw_protocol), ph->hook, plen);

        // debugging code to check packet
        struct iphdr *ip_header = payload;

        // Convert IP addresses to strings
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

        printf("Packet: src IP = %s, dst IP = %s, protocol = %u\n", 
                src_ip, dst_ip, ip_header->protocol);

        // Only interested in UDP, twamp uses it.
        if (ip_header->protocol == IPPROTO_UDP) {
                struct udphdr *udp_header = (struct udphdr *)((char *)ip_header + (ip_header->ihl * 4));
                uint16_t src_port = ntohs(udp_header->source);
                uint16_t dst_port = ntohs(udp_header->dest);
                
                printf("UDP: src port = %u, dst port = %u\n", src_port, dst_port);

                // Default port 4000 because of twamp servers.
                if (src_port == 4000 || dst_port == 4000) {
                printf("Potential TWAMP packet detected\n");
                }
        }

        if (attr[NFQA_CAP_LEN]) {
                uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
                if (orig_len != plen) {
                        printf("truncated ");
                }
        }

        if (skbinfo & NFQA_SKB_GSO) {
                printf("GSO ");
        }

        id = ntohl(ph -> packet_id);
        printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u",
                id, ntohs(ph->hw_protocol), ph->hook, plen);

        if (skbinfo & NFQA_SKB_CSUMNOTREADY)
                printf(", checksum not ready");
        puts("");

        if (drop_packet_parameter(id)) {
                apply_delay_packet();
                nfq_send_verdict(ntohs(nfg -> res_id), id, NF_ACCEPT);
        } else {
                printf("Dropping packet with id: %u\n", id);
                nfq_send_verdict(ntohs(nfg -> res_id), id, NF_DROP);
        }

        return MNL_CB_OK;
}

int main(int argc, char *argv[]) {

        char *buf;
        /* largest possible packet payload, plus netlink data overhead: */
        size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
        struct nlmsghdr *nlh;
        int ret;
        unsigned int portid, queue_num;

        printf("Main loop entered: \n");
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
                if (ret == -1)
                {
                        perror("mnl_socket_recvfrom");
                        exit(EXIT_FAILURE);
                }

                ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
                if (ret < 0)
                {
                        perror("mnl_cb_run");
                        exit(EXIT_FAILURE);
                }
        }

        mnl_socket_close(nl);

        return 0;
}