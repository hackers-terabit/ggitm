#ifndef NETWORK_H
#define NETWORK_H

#include <errno.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>

#include "main.h"
#include "util.h"
#include "macros.h"
#include "ggitm.h"

//sets up the interface and af_packet
int ifup (char *interface, int direction);
//reverse of above
int ifdown (char *interface);

void *capture_loop (void *arg);
void start_loops ();
void *copy_loop (void *arg);
void get_interface (char *if_name, struct ifreq *ifr, int d);
void write_out (int fd, int len, struct traffic_context tcx);
void sll_setup_out (char *interface, struct traffic_context *tcx);
void sll_setup_in (char *interface, struct traffic_context *tcx);

/*
 * left this here for referecne while coding
 struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    ihl:4,
                version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8    tos;
        __u16   tot_len;
        __u16   id;
        __u16   frag_off;
        __u8    ttl;
        __u8    protocol;
        __u16   check;
        __u32   saddr;
        __u32   daddr;
};

struct tcphdr {
        __u16   source;
        __u16   dest;
        __u32   seq;
        __u32   ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u16   res1:4,
                doff:4,
                fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u16   doff:4,
                res1:4,
                cwr:1,
                ece:1,
                urg:1,
                ack:1,
                psh:1,
                rst:1,
                syn:1,
                fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif  
        __u16   window;
        __u16   check;
        __u16   urg_ptr;
};
 */

struct ethh {
     uint8_t dst[6];
     uint8_t src[6];
     uint16_t ethtype;

};
struct PKT {
     uint8_t *ethernet_frame;
     struct iphdr *ipheader;
     struct udphdr *udpheader;
     struct tcphdr *tcpheader;
     uint8_t *data;
     uint16_t mtu;
     uint32_t len;
     uint32_t datalen;
};
void trace_dump (char *msg, struct PKT *packet);

#endif
