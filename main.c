#include "main.h"
#include "util.h"
int main (int argc, char **argv) {
  int i = 0;

  if (argc < 2)
    die (1, "Error,no arguments provided!\r\n");

  for (i; i < 32; i++)
    signal (i, signal_handler); //Setup signal handler

  parse_args (argc, argv, &global);
  INIT_LIST_HEAD (&HL.L);
  curl_global_init (CURL_GLOBAL_DEFAULT);

  load_whitelist (global.whitelist);
  load_blacklist (global.blacklist);
//TODO stuff :| maybe fork() around a bit once af_packet fanout is in effect?
  ifup (global.interface_in);
  capture_loop (global);
  ifdown (global.interface_in);
  curl_global_cleanup ();

  return 0;
}
