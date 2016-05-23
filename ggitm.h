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
#include "main.h"
#include "macros.h"

void http_dump (struct PKT *httppacket);        // trace_dump does this better,leaving it alone for now
/*
 * aquire value of "host:" header field 
 * we may not always have the host header,although testing has shown in most normal
 * applications,the host header is present,dnsmap is there as a placeholder in case figuring out the domain
 * by intercepting dns responses is needed.
*/
int get_http_host (char * data, char *buf, int bufsz);
inline int get_http_request (char * data, char *buf, int bufsz);
inline struct cache *search_cache (uint64_t uhash);
inline void add_cache (char *url, uint64_t match_hash, int response);
inline void del_cache (uint64_t hash);

int http_packet (struct traffic_context tcx);   //handler for all things http/global.http_port
void send_response (struct traffic_context tcx, char *host, char *request, char *url, int type);        //send appropriate http response,301 atm
void kill_session (struct traffic_context tcx);
void grack (struct PKT *pkt);   //gratiutous ack, probably don't need this,just a placeholder atm.
int redirect_ok (char *host, char *oldurl, char **newurl);
void check_redirect (char *url, int *state);    //curl and see if redirection would go through
void curl_opts (CURL * curl, char *url);
void rule_search (char *url, char *host);
void kill_session_server (struct traffic_context tcx);
void fill_payload (char *response_payload, char *host, char *url, char *request, int type);

#endif
