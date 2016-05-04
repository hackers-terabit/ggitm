#ifndef GGITM_H
#define GGITM_H
#define _GNU_SOURCE
#include "network.h"
#include "list.h"

void http_dump(struct PKT *httppacket);
int  get_http_host(uint8_t *data,char *buf,int bufsz);
void http_packet(struct PKT *httppacket);
void send_301(struct PKT *httppacket);
void kill_session(struct PKT*);
void grack(struct PKT *pkt);
int  redirect_ok(char *host);
void flow(struct PKT *httppacket);

#endif