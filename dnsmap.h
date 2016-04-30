#ifndef DNSMAP_H
#define DNSMAP_H
#include "network.h"

// need to map IP to dns for the 301 redirect
int init_dnsmap_table();
void free_dnsmap_table();

void dns_dump(struct PKT *dnspacket);

#endif