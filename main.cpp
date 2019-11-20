#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>

#include <string>
#include <iostream>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define TCP_PROTOCOL 6

using namespace std;

const string HTTPMETHOD[6] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
const string HOSTPREFIX = "Host: ";
string host;
ip* ip_header;
tcphdr* tcp_header;

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

void cdump(unsigned char* buf, int size) {
        int i;
        for (i = 0; i < size; i++) {
                if (i % 16 == 0) {
			if(i) {
				printf("   ");
				for(int j = i - 16; j < i; j++)
					printf("%c", buf[j] == 0x0a | buf[j] == 0x0d ? ' ' : buf[j]); 
			}
			printf("\n");
		}
                printf("%02x ", buf[i]);
        }
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, bool &flag)
{
	int id = 0;
	flag = true;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;
	
	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);
	
	memcpy(ip_header, data, sizeof(ip));
	if(ip_header->ip_v != IPVERSION) return id;
	if(ip_header->ip_p != TCP_PROTOCOL) return id;
	int ip_hl = 4 * ip_header->ip_hl;
	
	memcpy(tcp_header, data + ip_hl, sizeof(tcphdr));
	int tcp_hl = 4 * tcp_header->th_off;		

	int hl = ip_hl + tcp_hl;
	if(ret <= hl) return id;
	
	bool isStart = false, isWrite = false;
	for(auto method : HTTPMETHOD) {
		if(ret - hl < method.size()) continue;
		string str = "";
		for(int i = 0; i < method.size(); i++) str += data[hl + i];
		if(method == str) isStart = true;
	}
	
	if(!isStart) return id;
	string myhost = "";
	for(int i = hl; i < ret - HOSTPREFIX.size() + 1; i++) {
		bool cmp = true;
		for(int j = 0; j < HOSTPREFIX.size(); j++) {
			if(data[i + j] != HOSTPREFIX[j]) cmp = false;
		}
		if(cmp == true) isWrite = true, i+=HOSTPREFIX.size();
		if(isWrite && data[i] == 0x0d && data[i + 1] == 0x0a) break;
		if(isWrite) myhost += data[i];
	}

	flag = (host != myhost);
	
	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	bool flag = true;
	u_int32_t id = print_pkt(nfa, flag);
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, flag ? NF_ACCEPT : NF_DROP, 0, NULL);
}

void usage() {
	printf("syntax : netfilter_block <host>\n");
	printf("sample : netfilter_block test.gilgil.net\n");
}

int main(int argc, char **argv)
{
	if(argc != 2) {
		usage();
		return -1;
	}

	ip_header = (ip*) malloc(sizeof(ip));
	tcp_header = (tcphdr*) malloc(sizeof(tcphdr));
	host = argv[1];

	printf("host : %s, %s\n", host, argv[1]);
	cout << host << '\n';

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	free(ip_header);
	free(tcp_header);
	exit(0);
}

