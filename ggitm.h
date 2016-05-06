#ifndef GGITM_H
#define GGITM_H
#define _GNU_SOURCE

#include <curl/curl.h>
#include <time.h>

#include "util.h"
#include "list.h"



void http_dump (struct PKT *httppacket);        // trace_dump does this better,leaving it alone for now
/*
 * aquire value of "host:" header field 
 * we may not always have the host header,although testing has shown in most normal
 * applications,the host header is present,dnsmap is there as a placeholder in case figuring out the domain
 * by intercepting dns responses is needed.
*/
int get_http_host (uint8_t * data, char *buf, int bufsz);
void http_packet (struct PKT *httppacket);      //handler for all things http/global.http_port
void send_response (struct PKT *httppacket, char *host);        //send appropriate http response,301 atm
void kill_session (struct PKT *);       //placeholder for gracefully terminating the TCP session on behalf of client/server
void grack (struct PKT *pkt);   //gratiutous ack, probably don't need this,just a placeholder atm.
int redirect_ok (char *host);
void check_redirect (char *host);       //curl and see if redirection would go through


#endif
