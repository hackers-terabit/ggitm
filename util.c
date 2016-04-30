#include "util.h"

void
die (int really, char *why, ...) {
  char msg[245],color[256]="\033[1;31m";
  va_list arglist;

  va_start (arglist, why);
  
  vsnprintf (msg, 245, why, arglist);
  strncat(color,msg,256);
  va_end (arglist);

  if (really) {

    perror (color);
    debug (4, color);
    exit (really);
  }
  else {
    debug (4, color);
    perror (color);
  }

}


inline void
debug (int level, char *s,...) {

  if (global.debug >= level) {
//    logg (s);
  va_list arglist;

  va_start (arglist, s);
  vprintf (s, arglist);
  va_end (arglist);
  //printf ("\n");
  fflush (stdout);
  
  }
}

void
logg (char *s, ...) {

  va_list arglist;

  va_start (arglist, s);
  vprintf (s, arglist);
  va_end (arglist);
  printf ("\n");
  fflush (stdout);
}

inline unsigned short
csum (unsigned short *buf, int nwords) {
  unsigned long sum;

  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short) (~sum);
}

void drop_privs(){
  int ret=0;
  ret+=setgid (65533);
  ret+=setuid (65534);
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
  ret+=seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 2, 
                        SCMP_A0(SCMP_CMP_EQ, 1),
                        SCMP_A1(SCMP_CMP_EQ, 2));
  if(ret)
    die(1,"Error dropping priviledge!");
  ret=seccomp_load(ctx);
  if(ret <0)
    die(1,"Error loading SECCOMP!");
  seccomp_release(ctx);

}

void signal_handler(int signal){ 
  
// debug (0,"\033[1;31m***********************************SIGNAL(%d) CAUGHT******************************\n"
//,signal);

    switch (signal)
    {
    case SIGSEGV:
      die (0xDEAD,"Of all the things I've lost I miss my mind the most.\a\n");
      
      break;
    case SIGKILL:
       die(0xDEAD,"KILLED !!!\n");
      break;
    case SIGCHLD:
      printf ("Child process exited.\n");
      break;
    case SIGTERM:
         debug(0,"SIGTERM received. Termination signal will be sent to all threads.\n");
	 global.run=0;
      break;      
    case SIGTTOU:
    case SIGPROF :
     //   debug(4,"Profiling has started\n");
	break;
    default:
      die (1,"Houston We have a problem!!\n");
      return;
      break;
    }
}
void print_usage(){
 printf("Usage:\nggitm [-d] [-h] <-i interface> \n"
	 "-h        Display this help\n"
         "-d        Enable verbose debugging\n"
         "-i  interface      specify the interface the application will listen on,this is a mandatory option.\n" );
}
int parse_args(int argc,char **argv, struct global_settings *g){
  char c;
  int debug=4;
  
      while ((c = getopt(argc, argv, ":hd:i:")) != -1) {
               switch(c){
		 case 'd':
		   debug=atoi(optarg);
		   break;
		 case 'i':
		   strncpy(global.interface_in,optarg,IFNAMSIZ);
		   break;
		 case ':' :
  		   print_usage();
		   die(1,"%c requires an argument!\n",optopt);
		   break;
		 case 'h':
		   print_usage();
		   break;
		 default:
  		   print_usage();
		   die(1,"Error parsing config\n");
		   
	       }
      }
      global.debug=debug;
   
  return 0;
}
