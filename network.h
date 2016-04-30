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

void
get_interface (char *if_name, struct ifreq *ifr, int d);

struct PKT{
  uint8_t *ethernet_frame;
  struct iphdr *ipheader;
  struct udphdr *udpheader;
  struct tcphdr *tcpheader;
   uint8_t *data;
   int mtu;
   int len;
   int datalen;
};
void trace_dump (char *msg,struct PKT * packet);

#endif