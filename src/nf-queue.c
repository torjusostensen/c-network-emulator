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

static struct mnl_socket *nl;
static FILE *fp;

// Callback function for processing of each packet.
static int queue_cb(const struct nlmsghdr *nlh, void *data) {
        struct nfqnl_msg_packet_hdr *ph = NULL;
        struct nlattr *attr[NFQA_MAX + 1] = {};
        uint32_t id = 0, skbinfo;
        struct nfgenmsg *nfg;
        uint16_t plen;

        // Parse the netlink message.
        if (nfq_nlmsg_parse(nlh, attr) < 0) {
                perror("problems parsing");
                return MNL_CB_ERROR;
        }

        nfg = mnl_nlmsg_get_payload(nlh);

        // Checks if the packet has a header present.
        if (attr[NFQA_PACKET_HDR] == NULL) {
                fputs("metaheader not set\n", stderr);
                return MNL_CB_ERROR;
        }

        // Extract the packet information: Header, payload and other information.
        ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
        void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
        plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
        skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;
        id = ntohl(ph->packet_id);

        // Cast the payload to an IP header structure
        struct iphdr *ip_header = payload;
        struct udphdr *udp_header = (struct udphdr *)((char *)ip_header + (ip_header->ihl * 4));


        // Convert IP addresses to strings
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

        // Debug print to check that packet is received.
        printf("Packet received (id=%u hw=0x%04x hook=%u, payload len %u)\n", id, ntohs(ph->hw_protocol), ph->hook, plen);

        printf("Packet: src IP = %s, dst IP = %s, protocol = %u\n", 
                src_ip, dst_ip, ip_header->protocol);

        // Checks if package is UDP, not interested in other packets (twamp uses UDP).
        if (ip_header->protocol == IPPROTO_UDP) {
                uint16_t src_port = ntohs(udp_header->source);
                uint16_t dst_port = ntohs(udp_header->dest);

                printf("UDP: src port = %u, dst port = %u\n", src_port, dst_port);
        }

        // Check if the captured length attribute is present.
        if (attr[NFQA_CAP_LEN]) {
                // Retrieve the originial packet length before any truncation, and print "truncated" if it differs.
                uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
                if (orig_len != plen) {
                        printf("truncated ");
                }
        }

        // GSO = Generic Segmentation Offload
        if (skbinfo & NFQA_SKB_GSO) {
                printf("GSO ");
        }

        // Check if checksum is ready.
        if (skbinfo & NFQA_SKB_CSUMNOTREADY)
                printf(", checksum not ready");
        puts("");

        // BEGIN: Manipulation of packet stream
        int should_drop = should_drop_packet(id);
        if (should_drop) {
                nfq_send_verdict(ntohs(nfg -> res_id), id, NF_DROP);
                fprintf(fp, "%u, %s, %s, %u, %u, %u, %s, %.3f\n", id, src_ip, dst_ip, ip_header->protocol, ntohs(udp_header->source), ntohs(udp_header->dest), "dropped", apply_delay_packet());
                fflush(fp);
        } else {
                apply_delay_packet();
                nfq_send_verdict(ntohs(nfg -> res_id), id, NF_ACCEPT);
                fprintf(fp, "%u, %s, %s, %u, %u, %u, %s, %.3f\n", id, src_ip, dst_ip, ip_header->protocol, ntohs(udp_header->source), ntohs(udp_header->dest), "accepted", apply_delay_packet());
                fflush(fp);

        }
        // END: Manipulation of packet stream
        return MNL_CB_OK;
}

int main(int argc, char *argv[]) {
        srand((unsigned int) time(NULL));
        char *buf;
        /* largest possible packet payload, plus netlink data overhead: */
        size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
        struct nlmsghdr *nlh;
        int ret;
        unsigned int portid, queue_num;

        // Check that main loop is entered and correct number of arguments
        printf("Main loop entered: \n");
        if (argc != 2) {
                printf("Usage: %s [queue_num]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
        queue_num = atoi(argv[1]); // Set queue number equal to the input from command line interface

        // Open netlink socket
        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (nl == NULL) {
                perror("mnl_socket_open");
                exit(EXIT_FAILURE);
        }

        // Bind soccket to netfilter protocol
        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
                perror("mnl_socket_bind");
                exit(EXIT_FAILURE);
        }
        portid = mnl_socket_get_portid(nl); // Get the port id

        // Allocate memory for the buffer
        buf = malloc(sizeof_buf);
        if (!buf) {
                perror("allocate receive buffer");
                exit(EXIT_FAILURE);
        }

        fp = fopen("packet_log.csv", "w");
        if (fp == NULL) {
                perror("Error opening file");
                exit(EXIT_FAILURE);
        }

        // write header for csv file
        fprintf(fp, "ID,Source ip,Dest IP,Protocol,Source Port,Dest Port,Verdict,Delay\n");
        fflush(fp);

        // Prepare a netlink message to configure the queue
        nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
        nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

        // Send the netlink message to bind the queue
        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
                perror("mnl_socket_send");
                exit(EXIT_FAILURE);
        }

        // Prepare a netlink message to set packet copy mode
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
                // Receive packets from the netlink socket
                ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
                if (ret == -1)
                {
                        perror("mnl_socket_recvfrom");
                        exit(EXIT_FAILURE);
                }

                // Process the received packets using the callback function
                ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
                if (ret < 0)
                {
                        perror("mnl_cb_run");
                        exit(EXIT_FAILURE);
                }
        }
        // Close the netlink socket and the file
        mnl_socket_close(nl);
        fclose(fp);

        return 0;
}