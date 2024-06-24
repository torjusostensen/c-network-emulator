# include <stdio.h>
# include <stdlib.h>
# include <linux/netfilter.h>
# include <libnetfilter_queue/libnetfilter_queue.h>

// callback function to handle packets
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
        unsigned char *packet_data;
        struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);

        if (ph) {
                printf("Packet ID: %u\n", ntohl(ph -> packet_id)); // Printing the packet ID
        }

        int ret = nfq_get_payload(nfa, &packet_data); // Get packet payload
        if (ret >= 0) {
                printf("Payload length: %d\n", ret); // Printing the payload length
        }

        return nfq_set_verdict(qh, ntohl(ph -> packet_id), NF_ACCEPT, 0, NULL); // Accept the packet
}

int main(int arc, char **argv) {
        // Check if queue number argument is provided
        if (argc != 2) {
                fprintf(stderr, "Usage: %s <queue-num>\n", argv[0]);
                exit(EXIT_FAILURE);
        }

        // Parse queue number from command-line argument
        int queue_num = atoi(argv[1]);

        // Initialize netfilter queue variables
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        struct nfnl_handle *nh;
        int fd;
        int rv;
        char buf[4096] __attributes__((aligned));

        // Initialize library handle
        h = nfq_open();
        if (!h) {
                fprintf(stderr, "Error during nfq_open()\n");
                exit(EXIT_FAILURE);
        }

        // unbind existing nf_queue handler
        if (nfq_unbind_ph(h, AF_INET) < 0) {
                fprintf(stderr, "Error during nfq_unbind_pf()\n");
                nfq_close(h);
                exit(EXIT_FAILURE);
        }

        // bind nf_queue handler to AF_INET (IPv4) family
        if (nfq_bind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "Error during nfq_bind_pf()\n");
                nfq_close(h);
                exit(EXIT_FAILURE);
        }

        // Create queue handle
        qh = nfq_create_queue(h, queue_num, &cb, NULL);
        if (!qh) {
                fprintf(stderr, "Error during nfq_create_queue()\n");
                nfq_close(h);
                exit(EXIT_FAILURE);
        }

        // Set packet copy mode
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprint(stderr, "Cannot set packet_copy mode\n");
                nfq_destroy_queue(qh);
                nfq_close(h);
                exit(EXIT_FAILURE);
        }

        // Get file descriptor for queue
        fd = nfq_fd(h);

        // Main loop to handle packets
        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
                nfq_handle_packets(h, buf, rv);
        }

        // Cleanup
        nfq_destroy_queue(qh);
        nfq_close(h);

        return 0;
}