/*
 *
 *  Compile: gcc -o sn -l pcap -p pthread pt_sn.c
 *  Run: ./sn <ETH_INETRFACE_NAME> or ./sn
 *  Note: you need root privileges
 *  Created on: Feb 4, 2016
 *
 */
#include <pthread.h>
#include <pcap.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <sys/ioctl.h>
#include <linux/if.h>

#include <arpa/inet.h> // for inet_ntop

// Globals
int count;

pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
#define GL_MUTEX_LOCK        pthread_mutex_lock(&_mutex)
#define GL_MUTEX_UNLOCK      pthread_mutex_unlock(&_mutex)

pcap_t * handle_write; // Pcap handle for writing packages
                       // Handle MAC address
u_int8_t mac_address[6];
u_int32_t send_ip;

bpf_u_int32 mask;
bpf_u_int32 net;

// What kind of traffic we want to handler to supply for processing
#define MYFILTER "inbound and ip[4:2]==1137 and udp"

struct thread_info {
	pthread_t thread_id;
    int       thread_num;

    const struct pcap_pkthdr *header;
    const u_char *packet;

    const struct ether_header *ll_hdr; //packet link layer header
    const struct iphdr *ip_hdr; //packet ip header
    const struct udphdr *udp_hdr; //packet udp header

    const u_char *data; //packet payload
};

// This structure needs to be packed
struct thread_packet {
	struct ether_header eth;
	struct iphdr ip_header;
	struct udphdr udp_header;
	uint64_t data;
}__attribute__ ((__packed__)); // Please, don't

// From RStevense
uint16_t ip_checksum (const void * buf, size_t hdr_len) {
	unsigned long sum = 0;
	const uint16_t *ip1;

	ip1 = buf;
	while (hdr_len > 1){
		sum += *ip1++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		hdr_len -= 2;
	}

	if(hdr_len)
		sum += *ip1;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

   return(~sum);
}

//Thread function: need to return package to the sender
static void * thread_send(void *arg) {
	struct thread_info *tinfo = arg;
	struct thread_packet p;

	int ret = 0;

	fprintf(stderr, "Thread %lu  starts sending.\n", tinfo->thread_id);
	bzero(&p, sizeof(struct thread_packet));

	struct ether_header *ehdr = &(p.eth);
	const struct ether_header *peth = tinfo->ll_hdr;

	// Fill ETH header
	fprintf(stderr, "Prepare ETH header: ");
	printf( "HWaddr %02X:%02X:%02X:%02X:%02X:%02X\n",
				mac_address[0], mac_address[1], mac_address[2],
				mac_address[3], mac_address[4], mac_address[5] );
	ehdr->ether_type = peth->ether_type; // should be the same type

	memcpy((void *)&(ehdr->ether_dhost[0]), (void *)&(peth->ether_shost[0]), 6);
	printf( "DEST HWaddr %02X:%02X:%02X:%02X:%02X:%02X\n",
			ehdr->ether_dhost[0],
			ehdr->ether_dhost[1],
			ehdr->ether_dhost[2],
			ehdr->ether_dhost[3],
			ehdr->ether_dhost[4],
			ehdr->ether_dhost[5] );


	memcpy(&(ehdr->ether_shost), (void *)&(mac_address[0]), 6);
	printf( "SRC HWaddr %02X:%02X:%02X:%02X:%02X:%02X\n",
				ehdr->ether_shost[0],
				ehdr->ether_shost[1],
				ehdr->ether_shost[2],
				ehdr->ether_shost[3],
				ehdr->ether_shost[4],
				ehdr->ether_shost[5] );

	// IP header
	fprintf(stderr, "Prepare IP header.\n");
	struct iphdr *ip = &(p.ip_header);
	const struct iphdr *pip = tinfo->ip_hdr;

	u_int32_t sin = pip->saddr;
	u_int32_t des = pip->daddr;

	memcpy(ip, pip, 20);

	ip->daddr = sin;
	ip->saddr = send_ip;

	// Checksum
	ip->check = 0; // Fist set checksum to 0, then recalculate
	ip->check = ip_checksum(ip, 20);

	//Debug data
	char straddr[INET_ADDRSTRLEN];
	struct in_addr sin_addr;
	sin_addr.s_addr = ip->saddr;

	if (!inet_ntop(AF_INET, &sin_addr, straddr, sizeof straddr)) {
		 // Error
		fprintf(stderr, "Ops, something is wrong: %s.\n", strerror(errno));
		return NULL;
	}

	fprintf(stderr, "Set packet IP src: %s.\n", straddr);

	fprintf(stderr, "Prepare UDP header.\n");
	struct udphdr *udp = &(p.udp_header);
	const struct udphdr *pudp = tinfo->udp_hdr;
	uint16_t sp = pudp->source;
	uint16_t dp = pudp->dest;
	memcpy(udp, pudp, 8);
	udp->dest = sp;
	udp->source = dp;

	//Data
	uint64_t ntid = htobe64(tinfo->thread_id);
	p.data = ntid;

	//Debug the data we got
	char str[INET_ADDRSTRLEN];
	struct sockaddr_in sa;

	bzero(&sa, sizeof(struct sockaddr_in));
	sa.sin_addr.s_addr = ip->daddr;
	sa.sin_port = udp->dest;
	sa.sin_family = AF_INET;


	if (!(inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN))) {
		//Invalid
		fprintf(stderr, "Invalid destination address: %s \n", strerror(errno));
		return NULL;
	}


	fprintf(stderr, "Start sending to %s expected ETH[%d] IP[%d] UDP[%d] data[%d]bytes...\n",
				str, 	sizeof(struct ethhdr),
						sizeof(struct iphdr),
						sizeof(struct udphdr),
						sizeof(p.data));


	GL_MUTEX_LOCK;
	if (pcap_sendpacket(handle_write, (u_char *)&p, sizeof(struct thread_packet)) != 0 ) {
		// Some send error: no way to know  how many bytes are sent
		fprintf(stderr, "Unable to send: %s", strerror(errno));
	}
	GL_MUTEX_UNLOCK;
	//Lock the mutex, send the data and unlock the mutex
	fprintf(stderr, "OK, sent!\n");
	return NULL;
}

static const u_char *  process_packet_get_data(const struct pcap_pkthdr *header, const u_char *packet) {
	const u_char * prt 	=  NULL;
	int clen 			=  0;

	if ((!packet) || (!header))
			return NULL;

	prt  =  packet;
	clen = header->len;

	// Check the ETH header
	struct ether_header *eptr;
	eptr = (struct ether_header *) prt;

	if (ntohs (eptr->ether_type) != ETHERTYPE_IP) {
			fprintf(stderr,"ERROR, Not IP frame. Skip it!\n");
		    return NULL;
	}

	// Get to the IPv4 header
	if (clen < sizeof(struct ether_header)) {
		// No space for whole ETH header
		fprintf(stderr,"ERROR, Malformed ETH header. Skip it!\n");
	    return NULL;
	}

	fprintf(stderr, "Packet source HWaddr %02X:%02X:%02X:%02X:%02X:%02X\n",
				eptr->ether_shost[0],
				eptr->ether_shost[1],
				eptr->ether_shost[2],
				eptr->ether_shost[3],
				eptr->ether_shost[4],
				eptr->ether_shost[5] );

	clen -= sizeof(struct ether_header);

	// If we have IPv4 header at all.
	// It is variable in length, so this is not enough.
	if (clen < sizeof(struct iphdr)) {
		fprintf(stderr,"ERROR, Malformed IP header!\n");
		return NULL;
	}

	// Move the runner pointer to the IPv4 header
	const struct iphdr * piphdr = (struct iphdr *)(prt + sizeof(struct ether_header));

	u_int iph_len = ((piphdr)->ihl & 0x0f); // As IP header is variable in size, minimum 5 in 4B
	fprintf(stderr, "IP header length is %d\n", iph_len); // Needs to be 5

	if (iph_len < 5) {
		//ERROR
		fprintf(stderr, "ERROR, Invalid IP header length.\n");
		return NULL;
	}

	// Do we actually have these bytes
	if (clen < (iph_len*4) ) {
		//ERROR
		fprintf(stderr, "ERROR, Malformed IP header length.\n");
		return NULL;
	}

	//Get the total packet length : header and data in bytes
    u_int tlen     = ntohs(piphdr->tot_len);
    fprintf(stderr, "IP header total length is %d\n", tlen);
    if (clen < tlen) {
    	//ERROR
    	fprintf(stderr, "ERROR, Malformed IP packet.\n");
    	return NULL;
    }

    clen-=(iph_len*4); // Remove the IPv4 header length.

	// Get to the UDP header, check again
    if (clen < sizeof(struct udphdr)) {
    		//ERROR
    		fprintf(stderr, "ERROR, Malformed UDP header.\n");
    		return NULL;
    }

    struct udphdr *pudphdr = (struct udphdr *)(prt + 4*iph_len + sizeof(struct ether_header));
    fprintf(stderr, "UDP source port is %d\n", ntohs(pudphdr->source));

	clen -= sizeof(struct udphdr); //
	// We need to have 8B at least

	// TODO, CHANGE ME!
	if (clen < 8) {
		// Not enough space for the required payload
	   	fprintf(stderr, "ERROR, UDP payload needs to be 8B.\n");
	   	return NULL;

	}

	u_int udp_data_len = ntohs(pudphdr->len); // Payload and data

	fprintf(stderr, "INFO UDP payload size as specified into the header is %d.\n", udp_data_len);

	return (prt+ sizeof(struct udphdr) + 4*iph_len + sizeof(struct ether_header)); // At the beginning of the raw stream
}

// Main packet processing function;
static void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	//Parse the packet, if the packet is OK, read the data to spawn the threads

	int ret,i = 0;

	struct thread_info *tinfo;

	const u_char * data;

	fprintf(stderr, "Got a package matching filter");

	data = process_packet_get_data(header, packet);
	if (!data)
		return; // Invalid package

	//Try to parse the data: we are expecting to have 8B as payload
	uint64_t t = be64toh(*(uint64_t *)data);
	fprintf(stderr, "Threads we need to spawn: %ld\n", t);

	// Just a safe guard
	t = t % 100;//no more than this
	tinfo = calloc(t, sizeof(struct thread_info));

	// In the current context, we have need to have packet and header, as const pointers
	// to all the threads.
	// We are using threads, that we need to join, otherwise all we might end up with
	// overwritten package.
	for (i=0; i < t; i++) {

		//TODO: do not add directly, it could fail, only add successfully created threads
		tinfo[i].thread_num = i;
		tinfo[i].header = header;
		tinfo[i].packet = packet;
		tinfo[i].ll_hdr = (struct ether_header *)(packet);
		tinfo[i].ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
		tinfo[i].udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) +20);

		ret = pthread_create(&tinfo[i].thread_id, NULL, &thread_send, &tinfo[i]);
		if (ret != 0) {
			//Skip a beat
		}
	}

	for (i = 0; i < t; i++) {
		ret = pthread_join(tinfo[i].thread_id, NULL);
	}

	free(tinfo);

	return;
}

// Get the IP and MAC of a given device: this is used when constructing the response package
static int _sn_setup_write_handle(const char *dev) {
	struct ifreq s;
	int ret = 0;

	if (!dev)
		return -1;

	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (fd == -1) {
		// Error
		fprintf(stderr, "Could not create socket: %s", strerror(errno));
		return -1;
	}

	bzero(&s, sizeof(struct ifreq));

	strncpy(s.ifr_name, dev, sizeof(s.ifr_name));

	ret = ioctl(fd, SIOCGIFHWADDR, &s);

	if (!ret) {
		fprintf(stderr, "OK, got the MAC of %s\n", dev);

		memcpy( (void *)&mac_address[0], (void *)&s.ifr_ifru.ifru_hwaddr.sa_data[0], 6);

	}
	else {
		// Ioctl error
		fprintf(stderr, "IOCTL error: %s\n", strerror(errno));

		close(fd);

		return -1;
	}

	// Get the IP address list for the device
	bzero(&s, sizeof(struct ifreq));

	strncpy(s.ifr_name, dev, sizeof(s.ifr_name));

	ret = ioctl(fd, SIOCGIFADDR, &s);
	if (!ret) {

		fprintf(stderr, "OK got the IP of %s\n", dev);

		send_ip = ((struct sockaddr_in *)&s.ifr_addr)->sin_addr.s_addr;


	}
	else {
		fprintf(stderr, "IOCTL error: %s\n", strerror(errno));

		close(fd);

		return -1;
	}

	close(fd);

	return 0;
}

int main(int argc, char *argv[]){

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	pcap_t *handle_read;

	char *dev = NULL;

	if (argv[1]) {
		// User give us device name
		dev = argv[1];
	}

	if(!dev) {
		// Ask pcap for possible device
		dev = pcap_lookupdev(errbuf);

		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return -1;
		}
	}

	fprintf(stderr, "Using device: %s\n", dev);

	// Start with the read pcap handler: this one is used only for capturing
	handle_read = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (!handle_read) {
		fprintf(stderr, "ERROR Couldn't open read device %s: %s\n", dev, errbuf);
		return -1;
	}

	// Then the write pcap handle: this one is used only for writing
	handle_write = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (!handle_write) {
		fprintf(stderr, "ERROR Couldn't open write device %s: %s\n", dev, errbuf);
		return -1;
	}

	// Get the interface address and mask: how about the aliases
	pcap_lookupnet(dev, &net, &mask, errbuf); // TODO: error checking

	// Get write handle MAC and IP address
	_sn_setup_write_handle(dev); // TODO: error checking

	if (pcap_compile(handle_read, &fp, MYFILTER, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", MYFILTER, pcap_geterr(handle_read));
		return -1;
	}

	if (pcap_setfilter(handle_read, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle_read));
		return -1;
	}

	pcap_loop(handle_read, -1, process_packet, NULL);

	pcap_close(handle_read);
	pcap_close(handle_write);

	return 0;
}
