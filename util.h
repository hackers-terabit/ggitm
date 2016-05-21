#ifndef UTIL_H
#define UTIL_H
#define USE_OPENSSL

#ifdef USE_OPENSSL
#include <openssl/crypto.h>
#endif
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

#include "suricata/decode-ipv4.h"
#include "suricata/decode-ipv6.h"
#include "suricata/decode-tcp.h"

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
#define OL 1                    //out of line
#define IL 0                    // in line

#define HEADER_DEPTH 1024        // how many bytes into any packet's payload we'll look
#define URL_MAX 2000            // MS/IE have this at 2083,just to round it out since we may add / to the end in the response
#define CACHE_MAX 100000        // 100k cache entries by default
#define REDIRECT_MAX 9          //after 9 bogus redirects we will direct them back to their original host

#define REDIRECT_BW_FOUND 200   //BWL == black white list
#define REDIRECT_RULE_FOUND 300
#define REDIRECT_NEW  400
#define REDIRECT_EXPIRED 500
#define REDIRECT_DENIED 789

static const char *default_interface = "eth0";
static const char *redir_subd = "mtim";
//for now this is our curl UA:
static const char *UA = "Mozilla/5.0 (compatible; bluepacket/0.1a; +https://github.com/hackers-terabit/ggitm)";
uint64_t hashkey;

struct HDB {
     uint64_t host_hash;
     char host[LINE_LEN];
     uint16_t state;
     struct list_head L;
};

struct HDB HL;                  //host list

struct cache {
     int response;
     uint64_t match_url;
     char redirect_url[URL_MAX];
     struct list_head L;
};

struct cache CL;
int cache_lock, curl_lock;

extern char *optarg;
extern int optind, optopt;
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
int request_trim (char *str);
long checksum (unsigned short *addr, unsigned int count);
uint64_t rand_uint64_slow (void);
inline uint64_t string_to_hash (char *s);
void *malloc_or_die (char *str, size_t sz, ...);
void xnprintf (char *s, int max, char *format, ...);
inline int isnull_ (char *s);
inline int isnull (char *s);
 uint16_t ip_checksum(const void *buf, size_t hdr_len);
 inline uint16_t ip_fast_csum(const void *iph, unsigned int ihl);
#endif
