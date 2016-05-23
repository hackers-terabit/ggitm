#ifndef UTIL_H
#define UTIL_H

#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <seccomp.h>
#include <stdio.h>
#include <ctype.h>

#include "main.h"
#include "network.h"
#include "list.h"
#include "macros.h"

#include "suricata/decode-ipv4.h"
#include "suricata/decode-ipv6.h"
#include "suricata/decode-tcp.h"





extern char *optarg;
extern int optind, optopt;
FILE *openfile (char *path);

void load_whitelist (char *path);
void load_blacklist (char *path);
void load_hostlist (FILE * f, int type);
void host_to_url (int max, char *url, char *prefix, char *host, char *request);
void die (int really, char *why, ...);
void logg (char *s, ...);
void debug (int lvl, char *s, ...);
void drop_privs ();
void signal_handler (int sig);
void compute_tcp_checksum (struct iphdr *pIph, unsigned short *ipPayload);
void *malloc_or_die (char *str, size_t sz, ...);
void xprintf (char *s, int max, char *format, ...);
void cleanup();
void print_usage ();
void free_null(void *ptr);

int parse_args (int argc, char **argv, struct global_settings *g);
int request_trim (char *str);
long checksum (unsigned short *addr, unsigned int count);
uint64_t rand_uint64_slow (void);
inline uint64_t string_to_hash (char *s);

inline int isnull_ (char *s);
inline int isnull (char *s);
inline int atomic_lock (int *L);
inline int atomic_unlock (int *L) ;
int iscomment (char *s);
/** the following exists in siphash24.c ,not making a .h file for just one function **/
int crypto_auth (unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k) ;
/*
 uint16_t ip_checksum(const void *buf, size_t hdr_len);
 inline uint16_t ip_fast_csum(const void *iph, unsigned int ihl);
 unsigned short csum (unsigned short *buf, int nwords);
*/
#endif
