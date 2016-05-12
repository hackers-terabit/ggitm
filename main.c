#include "main.h"
#include "util.h"
#include "ruleparser.h"
#include "ggitm.h"

int main (int argc, char **argv) {
  int i = 0;

  if (argc < 2) {
    print_usage ();
    die (1, "Error,no arguments provided!\r\n");
  }

  for (i; i < 32; i++)
    signal (i, signal_handler); //Setup signal handler

  parse_args (argc, argv, &global);
  
  INIT_LIST_HEAD (&HL.L); //probably don't need this atm
  INIT_LIST_HEAD (&RL.L);
  INIT_LIST_HEAD (&CL.L);

  curl_global_init (CURL_GLOBAL_DEFAULT);
   global.cpu_available=sysconf(_SC_NPROCESSORS_CONF);
  hashkey=rand_uint64_slow();
  load_whitelist (global.whitelist);
  load_blacklist (global.blacklist);
  load_rules (global.rulepath);
  ifup (global.interface_in,1);
  if(!global.mode)
    ifup (global.interface_out,0);
  start_loops(); // start threads to copy traffic
  ifdown (global.interface_in);
  curl_global_cleanup ();

  return 0;
}
