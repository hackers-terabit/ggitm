#ifndef GGITM_H
#define GGITM_H
#define _GNU_SOURCE

#include <curl/curl.h>
#include <time.h>
#include <pcre.h>
#include <inttypes.h>
#include <pthread.h>

#include "util.h"
#include "ruleparser.h"
#include "list.h"
#include "pcrs/pcrs.h"

struct request{
  char url[2048];
  char *host;
};
struct cache{
  int response;
  uint64_t match_url;
  char redirect_url[URL_MAX];
  struct list_head L;
};

struct cache CL;
int cache_lock;

void http_dump (struct PKT *httppacket);        // trace_dump does this better,leaving it alone for now
/*
 * aquire value of "host:" header field 
 * we may not always have the host header,although testing has shown in most normal
 * applications,the host header is present,dnsmap is there as a placeholder in case figuring out the domain
 * by intercepting dns responses is needed.
*/
int get_http_host (uint8_t * data, char *buf, int bufsz);
inline int get_http_request (uint8_t * data, char *buf, int bufsz);
inline struct cache* search_cache(uint64_t uhash);
inline void add_cache(char *url,uint64_t match_hash,int response);

int  http_packet (struct PKT *httppacket,int socket,struct sockaddr_ll sll);      //handler for all things http/global.http_port
void send_response (struct PKT *httppacket,int socket,struct sockaddr_ll  sll, char *host, char *request, char *url, int type);    //send appropriate http response,301 atm
void kill_session (struct PKT *);       //placeholder for gracefully terminating the TCP session on behalf of client/server
void grack (struct PKT *pkt);   //gratiutous ack, probably don't need this,just a placeholder atm.
int redirect_ok (char *host, char *oldurl, char **newurl);
void check_redirect (char *url,int *state);       //curl and see if redirection would go through

void *rule_search_(void *r);
void *rule_search(void *);

int lookup_lock;
#endif
