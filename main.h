#ifndef MAIN_H
#define MAIN_H

#include <net/if.h>
#include <stdint.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <curl/curl.h>

struct global_settings {

  int debug;
  int run;
  char interface_in[IFNAMSIZ];
  char interface_out[IFNAMSIZ];
  char blacklist[256];
  char whitelist[256];
  int http_port;
  int https_port;
  int af_socket;
  int mode;
  struct sockaddr_ll sll;
};

struct global_settings global;

#endif
