#ifndef UTIL_H
#define UTIL_H

#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <seccomp.h>
#include <stdio.h>

#include "main.h"
#include "network.h"
#include "list.h"

#define IFINDEX 0
#define IFMTU 1
#define IFMAC 2
#define IFADDR 3

//ethernet and arp ...
#define ETH_HDRLEN 14
#define IP4_HDRLEN 20
#define ARP_HDRLEN 28
#define ARP_TIMEOUT 5
#define ETHIP4 IP4_HDRLEN + ETH_HDRLEN

#define COMMENT_CHAR '#'
#define LINE_LEN 256
#define WL 5500
#define BL 5511

#define HEADER_DEPTH 512        // how many bytes into any packet's payload we'll look

#define REDIRECT_FOUND 200
#define REDIRECT_NEW  300
#define REDIRECT_EXPIRED 400
#define REDIRECT_DENIED 9999

struct HDB {
  char host[LINE_LEN];
  uint16_t state;
  struct list_head L;
};


struct HDB HL;                  //host list

extern char *optarg;
extern int optind,
  optopt;
void load_whitelist (char *path);
void load_blacklist (char *path);
FILE *openfile (char *path);
int iscomment (char *s);
void load_hostlist (FILE * f, int type);
void die (int really, char *why, ...);
void logg (char *s, ...);
void debug (int lvl, char *s, ...);
void drop_privs ();
void signal_handler (int sig);
void compute_tcp_checksum (struct iphdr *pIph, unsigned short *ipPayload);
int parse_args (int argc, char **argv, struct global_settings *g);
void print_usage ();
unsigned short csum (unsigned short *buf, int nwords);

long checksum (unsigned short *addr, unsigned int count);


#endif
