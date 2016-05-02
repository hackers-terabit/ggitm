#ifndef MAIN_H
#define MAIN_H

#include <net/if.h>
#include <stdint.h>
#include <signal.h>



struct global_settings {
  
  int debug;
  int run;
  char interface_in[IFNAMSIZ];
  char interface_out[IFNAMSIZ];
  int http_port;
  int https_port;
  int af_socket;
  int mode;
};


struct global_settings global;

#endif