#include "main.h"
#include "ruleparser.h"
#include "ggitm.h"
#include "util.h"

int main (int argc, char **argv) {
     int i = 0;

     if (argc < 2) {
          print_usage ();
          die (1, "Error,no arguments provided!\r\n");
     }

     for (i=0; i < 32; i++)
          signal (i, signal_handler);   //Setup signal handler

     parse_args (argc, argv, &global);

     init_globals ();

     load_whitelist (global.whitelist);
     load_blacklist (global.blacklist);

     start_loops ();            // start threads to copy traffic
     destroy_globals ();

     return 0;
}

void init_globals () {
     INIT_LIST_HEAD (&global.HL.L);
     INIT_LIST_HEAD (&global.RL.L);
     INIT_LIST_HEAD (&global.CL.L);

     curl_global_init (CURL_GLOBAL_DEFAULT);
     global.cpu_available = sysconf (_SC_NPROCESSORS_CONF);
     global.hashkey = rand_uint64_slow ();
     ifup (global.interface_in, 1);
     if (global.mode == IL) {
          ifup (global.interface_out, 0);
          load_rules (global.rulepath);

     }
     global.failmode=1;
     global.fdcount=0;
     memset(global.fdlist,0,FD_MAX);
     global.delimiter = '`';
     global.default_interface = "eth0";
     global.UA = "Mozilla/5.0 (compatible; bluepacket/0.1a; +https://github.com/hackers-terabit/ggitm)";
     global.redir_subd = "mtim";
}

void destroy_globals () {

     curl_global_cleanup ();
     ifdown (global.interface_in);
}


