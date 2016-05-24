#ifndef MAIN_H
#define MAIN_H

#include <net/if.h>
#include <stdint.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <curl/curl.h>
#include <unistd.h>
#include <pthread.h>
#include "list.h"
#include "pcrs/pcrs.h"
#include "macros.h"

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
struct traffic_context {
     struct PKT *pkt;
     struct sockaddr_ll sll_in, sll_out;
     int fd_in, fd_out;
     struct ethh mac_in,mac_out;
};

struct HDB {
     uint64_t host_hash;
     char host[LINE_LEN];
     uint16_t state;
     struct list_head L;
};

struct cache {
     int response;
     uint64_t match_url;
     char redirect_url[URL_MAX];
     struct list_head L;
};
struct rules {
     pcrs_job *job;
     pcre *targets[MAX_REGEX];
     int target_count;
     char name[256];
     struct list_head L;
};

struct global_settings {

     int debug;
     int run;
     char interface_in[IFNAMSIZ];
     char interface_out[IFNAMSIZ];
     int cpu_available;
     char blacklist[256];
     char whitelist[256];
     char rulepath[256];
     int http_port;
     int https_port;
     int failmode;              //0 (default)= fail closed, 1= failopen
     int mode;

     char *default_interface;
//for now this is our curl UA:
     char *UA;
     uint64_t hashkey;

     struct HDB HL;             //host list
     struct cache CL;
     int cache_lock, curl_lock;

     int fdlist[FD_MAX];
     int fdcount;

//yeah this seems a bit messy...
     pthread_t capture_handle[TMAX], copy_handle[TMAX];
     int tcount;

     struct rules RL;           //rule list
     char delimiter;            //why not,hope nobody uses ` in their url :P
     int lookup_lock;
     char *redir_subd;
};

struct global_settings global;

void destroy_globals ();
void init_globals ();
#endif
