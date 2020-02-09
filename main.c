#include <linux/ioctl.h>
#include <linux/if.h>
#include <linux/if_tunnel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>


typedef struct
{
	__u16 flags;
	__u16 bytelen;
	__s16 bitlen;
	/* These next two fields match rtvia */
	__u16 family;
	__u32 data[64];
} inet_prefix;
enum {
  IPPROTO_IP = 0,		/* Dummy protocol for TCP		*/
#define IPPROTO_IP		IPPROTO_IP
  IPPROTO_ICMP = 1,		/* Internet Control Message Protocol	*/
#define IPPROTO_ICMP		IPPROTO_ICMP
  IPPROTO_IGMP = 2,		/* Internet Group Management Protocol	*/
#define IPPROTO_IGMP		IPPROTO_IGMP
  IPPROTO_IPIP = 4,		/* IPIP tunnels (older KA9Q tunnels use 94) */
#define IPPROTO_IPIP		IPPROTO_IPIP
  IPPROTO_TCP = 6,		/* Transmission Control Protocol	*/
#define IPPROTO_TCP		IPPROTO_TCP
  IPPROTO_EGP = 8,		/* Exterior Gateway Protocol		*/
#define IPPROTO_EGP		IPPROTO_EGP
  IPPROTO_PUP = 12,		/* PUP protocol				*/
#define IPPROTO_PUP		IPPROTO_PUP
  IPPROTO_UDP = 17,		/* User Datagram Protocol		*/
#define IPPROTO_UDP		IPPROTO_UDP
  IPPROTO_IDP = 22,		/* XNS IDP protocol			*/
#define IPPROTO_IDP		IPPROTO_IDP
  IPPROTO_TP = 29,		/* SO Transport Protocol Class 4	*/
#define IPPROTO_TP		IPPROTO_TP
  IPPROTO_DCCP = 33,		/* Datagram Congestion Control Protocol */
#define IPPROTO_DCCP		IPPROTO_DCCP
  IPPROTO_IPV6 = 41,		/* IPv6-in-IPv4 tunnelling		*/
#define IPPROTO_IPV6		IPPROTO_IPV6
  IPPROTO_RSVP = 46,		/* RSVP Protocol			*/
#define IPPROTO_RSVP		IPPROTO_RSVP
  IPPROTO_GRE = 47,		/* Cisco GRE tunnels (rfc 1701,1702)	*/
#define IPPROTO_GRE		IPPROTO_GRE
  IPPROTO_ESP = 50,		/* Encapsulation Security Payload protocol */
#define IPPROTO_ESP		IPPROTO_ESP
  IPPROTO_AH = 51,		/* Authentication Header protocol	*/
#define IPPROTO_AH		IPPROTO_AH
  IPPROTO_MTP = 92,		/* Multicast Transport Protocol		*/
#define IPPROTO_MTP		IPPROTO_MTP
  IPPROTO_BEETPH = 94,		/* IP option pseudo header for BEET	*/
#define IPPROTO_BEETPH		IPPROTO_BEETPH
  IPPROTO_ENCAP = 98,		/* Encapsulation Header			*/
#define IPPROTO_ENCAP		IPPROTO_ENCAP
  IPPROTO_PIM = 103,		/* Protocol Independent Multicast	*/
#define IPPROTO_PIM		IPPROTO_PIM
  IPPROTO_COMP = 108,		/* Compression Header Protocol		*/
#define IPPROTO_COMP		IPPROTO_COMP
  IPPROTO_SCTP = 132,		/* Stream Control Transport Protocol	*/
#define IPPROTO_SCTP		IPPROTO_SCTP
  IPPROTO_UDPLITE = 136,	/* UDP-Lite (RFC 3828)			*/
#define IPPROTO_UDPLITE		IPPROTO_UDPLITE
  IPPROTO_MPLS = 137,		/* MPLS in IP (RFC 4023)		*/
#define IPPROTO_MPLS		IPPROTO_MPLS
  IPPROTO_RAW = 255,		/* Raw IP packets			*/
#define IPPROTO_RAW		IPPROTO_RAW
  IPPROTO_MAX
};
enum {
	PREFIXLEN_SPECIFIED	= (1 << 0),
	ADDRTYPE_INET		= (1 << 1),
	ADDRTYPE_UNSPEC		= (1 << 2),
	ADDRTYPE_MULTI		= (1 << 3),

	ADDRTYPE_INET_UNSPEC	= ADDRTYPE_INET | ADDRTYPE_UNSPEC,
	ADDRTYPE_INET_MULTI	= ADDRTYPE_INET | ADDRTYPE_MULTI
};
/* This uses a non-standard parsing (ie not inet_aton, or inet_pton)
 * because of legacy choice to parse 10.8 as 10.8.0.0 not 10.0.0.8
 */
static int get_addr_ipv4(__u8 *ap, const char *cp)
{
	int i;

	for (i = 0; i < 4; i++) {
		unsigned long n;
		char *endp;

		n = strtoul(cp, &endp, 0);
		if (n > 255)
			return -1;	/* bogus network value */

		if (endp == cp) /* no digits */
			return -1;

		ap[i] = n;

		if (*endp == '\0')
			break;

		if (i == 3 || *endp != '.')
			return -1;	/* extra characters */
		cp = endp + 1;
	}

	return 1;
}

int af_bit_len(int af)
{
	switch (af) {
	case AF_INET6:
		return 128;
	case AF_INET:
		return 32;
	case AF_DECnet:
		return 16;
	case AF_IPX:
		return 80;
	case AF_MPLS:
		return 20;
	}

	return 0;
}

static int af_byte_len(int af)
{
	return af_bit_len(af) / 8;
}
static int __get_addr_1(inet_prefix *addr, const char *name, int family)
{
	memset(addr, 0, sizeof(*addr));

	if (strcmp(name, "default") == 0) {
		if ((family == AF_DECnet) || (family == AF_MPLS))
			return -1;
		addr->family = family;
		addr->bytelen = af_byte_len(addr->family);
		addr->bitlen = -2;
		addr->flags |= PREFIXLEN_SPECIFIED;
		return 0;
	}

	if (strcmp(name, "all") == 0 ||
	    strcmp(name, "any") == 0) {
		if ((family == AF_DECnet) || (family == AF_MPLS))
			return -1;
		addr->family = family;
		addr->bytelen = 0;
		addr->bitlen = -2;
		return 0;
	}

	if (strchr(name, ':')) {
		addr->family = AF_INET6;
		if (family != AF_UNSPEC && family != AF_INET6)
			return -1;
		addr->bytelen = 16;
		addr->bitlen = -1;
		return 0;
	}



	addr->family = AF_INET;

	if (get_addr_ipv4((__u8 *)addr->data, name) <= 0)
		return -1;

	addr->bytelen = 4;
	addr->bitlen = -1;
	return 0;
}

static void set_address_type(inet_prefix *addr)
{
	switch (addr->family) {
	case AF_INET:
		if (!addr->data[0])
			addr->flags |= ADDRTYPE_INET_UNSPEC;
		else
			addr->flags |= ADDRTYPE_INET;
		break;
	case AF_INET6:
			addr->flags |= ADDRTYPE_INET;
		break;
	}
}
int get_addr_1(inet_prefix *addr, const char *name, int family)
{
	int ret;

	ret = __get_addr_1(addr, name, family);
	if (ret)
		return ret;

	set_address_type(addr);
	return 0;
}

__u32 get_addr32(const char *name)
{
	inet_prefix addr;

	if (get_addr_1(&addr, name, AF_INET)) {
		fprintf(stderr,
			"Error: an IP address is expected rather than \"%s\"\n",
			name);
		exit(1);
	}
	return addr.data[0];
}


int check_ifname(const char *name)
{
	/* These checks mimic kernel checks in dev_valid_name */
	if (*name == '\0')
		return -1;
	if (strlen(name) >= IFNAMSIZ)
		return -1;

	while (*name) {
		if (*name == '/'|| *name ==' ')
			return -1;
		++name;
	}
	return 0;
}
/* buf is assumed to be IFNAMSIZ */
int get_ifname(char *buf, const char *name)
{
	int ret;

	ret = check_ifname(name);
	if (ret == 0)
		strncpy(buf, name, 5);

	return ret;
}
int main()
{
	struct ifreq *ifr;
	int fd=0;
	int err=0;
	struct ip_tunnel_parm *p;
	char basedev[4] ="gre\0";
	char tunnelname[5] = "gre1\0";
	const char remote_addr[12]="192.168.1.7\0";
	const char local_addr[13]="192.168.1.39\0";

	p   = (struct ip_tunnel_parm *) malloc(sizeof(struct ip_tunnel_parm));
	ifr = (struct ifreq *)          malloc(sizeof(struct ifreq));
	memset(p, 0, sizeof(struct ip_tunnel_parm));
	memset(ifr, 0, sizeof(struct ifreq));

	p->iph.version = 4;
	p->iph.ihl = 5;
	p->iph.protocol =IPPROTO_GRE;
	p->iph.daddr= get_addr32(remote_addr);// remote addr
	p->iph.saddr = get_addr32(local_addr);// local addr
	get_ifname(p->name,tunnelname) ; //set name
	strncpy(ifr->ifr_name, basedev, sizeof(basedev));

	printf("Tunnel type [%.*s][len : %ld ] \n",(int)strlen(ifr->ifr_name),ifr->ifr_name,sizeof(basedev));
	printf("Tunnel name [%.*s]  \n",(int)strlen(p->name),p->name);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
			fprintf(stderr, "create socket failed: \n");
			return -1;
		}

	ifr->ifr_ifru.ifru_data = p;
  err = ioctl(fd, SIOCADDTUNNEL, ifr);
	if (err){
		fprintf(stderr, "add tunnel \"%s\" failed:[%d]\n", ifr->ifr_name,err);
		}
	close(fd);
	return err;
}
