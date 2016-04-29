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


extern char *optarg;
extern int optind, optopt;




void die (int really, char *why, ...);
void logg (char *s, ...);
void debug (int lvl, char *s,...);
void drop_privs();
void signal_handler(int sig);

int parse_args(int argc,char **argv, struct global_settings *g);
void print_usage();
unsigned short csum (unsigned short *buf, int nwords);


#endif