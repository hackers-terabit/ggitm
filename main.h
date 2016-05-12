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

struct global_settings {

  int debug;
  int run;
  char interface_in[IFNAMSIZ];
  char interface_out[IFNAMSIZ];
  int  cpu_available;
  char blacklist[256];
  char whitelist[256];
  char rulepath[256];
  int http_port;
  int https_port;
  int af_socket;
  int af_socket_out;
  int mode;
  struct sockaddr_ll sll,sll_out;
};

struct global_settings global;

#endif
