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

#include "main.h"
#include "util.h"
//sets up the interface and af_packet
int ifup (char *interface);
//reverse of above
int ifdown (char *interface);

/* main running loop, inspects packets,interacts with dnsmap
interacts with ggitm.c stuff.
The idea at this time is we treat packets as "events"
and call functions based on the type of packet. 

capture_loop will feed dnsmap dns packets.
and ggitm will be fed HTTP packets.
ggitm as needed will query dnsmap for domain name to be used in the 301 redirect.

ggitm and dnsmap will decide on how their respective packets are handled.

Ideally ggitm will also build a linked-list of white listed domains that will not be redirected.

Eventually capture_loop should query a socket or signal to suspend operations which will cause it to 
passthrough all packets without querying dnsmap or ggitm.

*/
void capture_loop (struct global_settings global);

void get_interface (char *if_name, struct ifreq *ifr, int d);
/* left this here for referecne while coding
 00169 struct iphdr {
00170 #if defined(__LITTLE_ENDIAN_BITFIELD)
00171         __u8    ihl:4,
00172                 version:4;
00173 #elif defined (__BIG_ENDIAN_BITFIELD)
00174         __u8    version:4,
00175                 ihl:4;
00176 #else
00177 #error  "Please fix <asm/byteorder.h>"
00178 #endif
00179         __u8    tos;
00180         __u16   tot_len;
00181         __u16   id;
00182         __u16   frag_off;
00183         __u8    ttl;
00184         __u8    protocol;
00185         __u16   check;
00186         __u32   saddr;
00187         __u32   daddr;
00188         /*The options start here. 
00189 };

00023 struct tcphdr {
00024         __u16   source;
00025         __u16   dest;
00026         __u32   seq;
00027         __u32   ack_seq;
00028 #if defined(__LITTLE_ENDIAN_BITFIELD)
00029         __u16   res1:4,
00030                 doff:4,
00031                 fin:1,
00032                 syn:1,
00033                 rst:1,
00034                 psh:1,
00035                 ack:1,
00036                 urg:1,
00037                 ece:1,
00038                 cwr:1;
00039 #elif defined(__BIG_ENDIAN_BITFIELD)
00040         __u16   doff:4,
00041                 res1:4,
00042                 cwr:1,
00043                 ece:1,
00044                 urg:1,
00045                 ack:1,
00046                 psh:1,
00047                 rst:1,
00048                 syn:1,
00049                 fin:1;
00050 #else
00051 #error  "Adjust your <asm/byteorder.h> defines"
00052 #endif  
00053         __u16   window;
00054         __u16   check;
00055         __u16   urg_ptr;
00056 };
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
