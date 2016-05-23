#include "util.h"

void die (int really, char *why, ...) {
     char msg[245], color[256] = "\033[1;31m";
     va_list arglist;

     va_start (arglist, why);

     snprintf (msg, 245, why, arglist);
     strncat (color, msg, 256);
     va_end (arglist);

     if (really) {

          perror (color);
          debug (4, color);
          exit (really);
     } else {
          debug (4, color);
          perror (color);
     }

}

inline void debug (int level, char *s, ...) {

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

void logg (char *s, ...) {

     va_list arglist;

     va_start (arglist, s);
     vprintf (s, arglist);
     va_end (arglist);
     printf ("\n");
     fflush (stdout);
}
inline int isnull (char *s) {
     if (s == NULL)
          return 1;
     else
          return 0;
}
inline int isnull_ (char *s) {
     int ret = isnull (s);
     if (ret)
          return ret;
     if (strlen (s) < 1)
          return 1;

     return 0;
}
void xprintf (char *s, int max, char *format, ...) {
     va_list ap;
     va_start (ap, format);
     if (isnull (s))
          die (1, "CRITICAL ERROR! attempted xprintf() received a null string or an empty format string\r\n");

     int ret = vsnprintf (s, max, format, ap);
     va_end (ap);
     if (ret < 0) {
          die (0, "xprintf() output error for %s\r\n", s);
     } else if (ret > max) {
          printf ("%i bytes truncated while doing xprintf()", max - ret);
     }
}

void drop_privs () {
     int ret = 0;
     setgid (65533);
     setuid (65534);
     scmp_filter_ctx ctx;
     ctx = seccomp_init (SCMP_ACT_ALLOW);

     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (poll), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (read), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (write), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (sendto), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (sendmmsg), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (connect), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (rt_sigaction), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (open), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (close), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (getpeername), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (mmap), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (fstat), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (socket), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (recvmsg), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (getsockname), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (alarm), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (munmap), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (rt_sigprocmask), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (fcntl), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (getsockopt), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (recvfrom), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (stat), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (brk), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (lseek), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (mprotect), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (access), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (getpid), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (bind), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (execve), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (uname), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (getuid), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (setuid), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (setgid), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (prctl), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (arch_prctl), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (getdents), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (openat), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (seccomp), 0);

     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (ioctl), 1, SCMP_A1 (SCMP_CMP_EQ, (int) SIOCGIFMTU));
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (ioctl), 1, SCMP_A1 (SCMP_CMP_EQ, (int) SIOCGIFINDEX));
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (ioctl), 1, SCMP_A1 (SCMP_CMP_EQ, (int) SIOCGIFFLAGS));
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (ioctl), 1, SCMP_A1 (SCMP_CMP_EQ, (int) FIONREAD));

     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (exit_group), 0);
     ret += seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (futex), 0);
     ret +=
          seccomp_rule_add (ctx, SCMP_ACT_ALLOW, SCMP_SYS (dup2), 2, SCMP_A0 (SCMP_CMP_EQ, 1),
                            SCMP_A1 (SCMP_CMP_EQ, 2));
     ret = seccomp_load (ctx);
     if (ret < 0)
          die (1, "Error loading SECCOMP!");
     seccomp_release (ctx);

}
int request_trim (char *s) {
     char buf[HEADER_DEPTH];
     memset (buf, 0, HEADER_DEPTH);
     if (s == NULL)
          return 0;
     int len = strlen (s);
     if (len < 2)
          return 0;
     int i = 0, num;

     int len_r = strlen (global.redir_subd);
     for (i = 0; i < len && i < HEADER_DEPTH; i++) {
          if (isspace (s[i]))
               continue;
          else
               break;

     }
     s = &s[i];

     len = strlen (s);
     if (len < (len_r + 2))
          return 0;
     for (; i < strlen (s) && i < HEADER_DEPTH; i++)
          if (s[0] == '/')
               s = &s[i + 1];
     if (strlen (s) < (len_r + 2))
          return 0;

     if (memcmp (s, global.redir_subd, len_r) == 0 && isdigit (s[len_r])) {
          debug (6, "%s matches and digit found %c\r\n", s, s[len_r]);

          i += (len_r);
          num = atoi (&s[len_r]);
          debug (6, "extracted number %i,real request:%s\r\n", num, &s[i]);
          len = strlen (&s[i]);
          strncpy (buf, &s[i], HEADER_DEPTH);
          buf[strlen (buf) - (len + 1)] = '\0';
          memset (s, 0, strlen (s));
          strncpy (s, buf, HEADER_DEPTH);
          return num;
     } else {
          debug (6, "host:%s didn't match %s\r\n", s, global.redir_subd);
     }
     return 0;
}
void *malloc_or_die (char *str, size_t sz, ...) {
     if (str == NULL || strlen (str) < 1)
          die (1, "Error,malloc_or_die() with an empty message");
     char *ret = malloc (sz);
     va_list ap;
     if (ret == NULL)
          die (1, str, ap);
     memset (ret, 0, sz);
     return (void *) ret;
}
void free_null (void *ptr) {
     if (ptr != NULL) {
          free (ptr);
          ptr = NULL;
     }

}
uint64_t rand_uint64_slow (void) {
     srand (time (NULL));
     uint64_t r = 0;
     int i = 0;
     for (i = 0; i < 64; i++) {
          r = r * 2 + rand () % 2;
     }
     return r;
}

void signal_handler (int signal) {

// debug (0,"\033[1;31m***********************************SIGNAL(%d) CAUGHT******************************\n"
//,signal);

     switch (signal) {
     case SIGSEGV:
          die (0xDEAD, "Of all the things I've lost I miss my mind the most.\a\n");

          break;
     case SIGKILL:
          die (0xDEAD, "KILLED !!!\n");
          break;
     case SIGCHLD:
          printf ("Child process exited.\n");
          break;
     case SIGTERM:
          debug (0, "SIGTERM received. Termination signal will be sent to all threads.\n");
          global.run = 0;
          break;
     case SIGTTOU:
     case SIGPROF:
          debug (4, "Profiling has started\n");
          break;
     case 33:
          break;
     default:
          cleanup ();
          die (1, "Houston We have a problem!!\n");
          return;
          break;
     }
}
void print_usage () {
     printf
          ("Usage:\nggitm  <-i interface> [-d <0-7>] [-h] [-m <il,ol,outofline,inline>] [-T https_port] [-H http_port] \n"
           "-h                           Display this help\n"
           "-d <0-7>                     Enable verbose debugging,0 is quiet,7 is noisy\n"
           "-i <interface>               the input interface  the application will listen on,this is a mandatory option.\n"
           "-o <interface>               the output interface for inline mode (mandatory for inline mode of operation)\r\n"
           "-m {inline,il,outofline,ol}  the mode of operation,only one mode of operation allowed.\r\n"
           "-T <1-65535>                 the HTTPS port it will attempt to redirect to\r\n"
           "-H <1-65535>                 the HTTP port it will attempt to intercept for redirection\r\n"
           "-w /path/whitelist           file system path to a file containing line separated entries of whitelisted domains\r\n"
           "-b /path/blacklist           file system path to a file containing line separated entries of blacklisted domains\r\n"
           "-r /path/rule/               file system path to a directory containing httpseverywhere compatible xml rules\r\n");
}
int parse_args (int argc, char **argv, struct global_settings *g) {
     char c;
     int debug = 4, h = 80, t = 443;
     char mode[32];
     char wl_path[256] = "";
     char bl_path[256] = "";
     char rl_path[256] = "";
     memset (mode, 0, 32);
     while ((c = getopt (argc, argv, ":hd:i:o:T:H:m:w:b:r:")) != -1) {
          switch (c) {
          case 'd':
               debug = atoi (optarg);
               break;
          case 'T':
               t = atoi (optarg);
               break;
          case 'H':
               h = atoi (optarg);
               break;
          case 'm':
               strncpy (mode, optarg, 10);
               break;
          case 'o':
               strncpy (global.interface_out, optarg, IFNAMSIZ);
               break;
          case 'i':
               strncpy (global.interface_in, optarg, IFNAMSIZ);
               break;
          case ':':
               print_usage ();
               die (1, "%c requires an argument!\n", optopt);
               break;
          case 'h':
               print_usage ();
               exit (0);
               break;
          case 'w':
               strncpy (wl_path, optarg, 256);
               break;
          case 'b':
               strncpy (bl_path, optarg, 256);
               break;
          case 'r':
               strncpy (rl_path, optarg, 256);
               break;
          default:
               print_usage ();
               die (1, "Error parsing config\n");

          }
     }
     printf ("\r\n---------------------------------------------------\r\n");
     if (h < 1 || h > 65535)
          die (1, "Invalid HTTP port number");

     global.http_port = h;

     if (t < 1 || t > 65535)
          die (1, "Invalid HTTPS port number");

     global.https_port = t;

     logg ("HTTP port:%i \r\nHTTPS port:%i\r\n", global.http_port, global.https_port);
     if (strlen (global.interface_in) < 2)
            strncpy (global.interface_in, global.default_interface, IFNAMSIZ);

     if (strlen (mode) < 2)
          global.mode = OL;
     else {
          if (strncmp (mode, "inline", 6) == 0 || strncmp (mode, "il", 2) == 0) {
               global.mode = IL;
               if (strlen (global.interface_out) < 2 || strlen (global.interface_in) < 2)
                      die (1, "Invalid interfaces selected for inline mode of operation: In:%s Out:%s",
                           global.interface_in, global.interface_out);

               logg ("Inline mode of operation selected.");
          } else if (strncmp (mode, "outofline", 9) == 0 || strncmp (mode, "ol", 2) == 0) {
               global.mode = OL;
               if (strlen (global.interface_in) < 2)
                      die (1, "Invalid input interface for out of line mode of operation: %s", global.interface_in);

               logg ("Out of line mode of operation selected. We will only use black/white list based redirection.");

          }
     }
     logg ("Input interface %s\r\nOutput interface %s\r\n", global.interface_in, global.interface_out);

     global.debug = debug;
     logg ("Debug level set to %i\r\n", global.debug);
     if (strlen (wl_path) < 2)
          strncpy (global.whitelist, "./whitelist", strlen ("./whitelist"));
     else
          strncpy (global.whitelist, wl_path, 256);

     if (strlen (bl_path) < 2)
          strncpy (global.blacklist, "./blacklist", strlen ("./blacklist"));
     else
          strncpy (global.blacklist, bl_path, 256);

     if (strlen (rl_path) < 2)
          strncpy (global.rulepath, "./rules", strlen ("./rules"));
     else
          strncpy (global.rulepath, rl_path, 256);

     logg ("White-list file path set to %s", global.whitelist);
     logg ("Black-list file path set to %s", global.blacklist);
     logg ("XML rule  path set to %s", global.rulepath);

     printf ("\r\n---------------------------------------------------\r\n");
     return 0;
}
FILE *openfile (char *path) {
     FILE *f;
     if (strlen (path) < 1)
          die (1, "File path too short,exiting now.");

     f = fopen (path, "r");
     if (f == NULL)
          die (1, "Failed to open file %s,exiting now.", path);

     return f;
}
int iscomment (char *s) {
     int i = 0, len = strlen (s);

     if (len > 0) {
          for (i = 0; i < len && i < LINE_LEN; i++) {
               if (!isblank (s[i])) {
                    if (s[i] == COMMENT_CHAR)
                         return 1;
                    else
                         return 0;
               }
          }
     }
     return 0;
}
void host_to_url (int max, char *url, char *prefix, char *host, char *request) {
     if (max < 2 || url == NULL || prefix == NULL || host == NULL)
          return;
     int hlen = 0, plen = 0, rlen = 0;
     if (request == NULL || strlen (request) < 1)
          rlen = 0;
     else
          rlen = strlen (request);

     hlen = strlen (host);
     plen = strlen (prefix);

     if (hlen < 1 || plen < 1)
          return;
     memset (url, 0, max);
     if (rlen > 0) {
          debug (7, "Converting to https: %s + %s + %s\r\n", prefix, host, request);

          if (request[0] != '/')
               xprintf (url, max, "%s%s/%s", prefix, host, request);
          else
               xprintf (url, max, "%s%s%s", prefix, host, request);
     } else {
          xprintf (url, max, "%s%s/", prefix, host);

     }
}
void load_blacklist (char *path) {
     FILE *f;

     f = openfile (path);
     load_hostlist (f, BL);
     debug (5, "Finished loading blacklist entries from %s\r\n", path);

     fclose (f);
}
void load_whitelist (char *path) {
     FILE *f;

     f = openfile (path);
     load_hostlist (f, WL);
     debug (5, "Finished loading whitelist entries from %s\r\n", path);

     fclose (f);
}
void load_hostlist (FILE * f, int type) {
     int i, len;
     struct HDB *entry;
     struct chache *cob;
     char line[LINE_LEN], redirecturl[LINE_LEN];
     memset (line, 0, LINE_LEN);

     while (!feof (f)) {
          if (fgets (line, LINE_LEN, f) == NULL)
               continue;
          len = strlen (line);

          if (len < 2 || iscomment (line))
               continue;
          entry = malloc_or_die ("Failed to allocate entry memory while loading host list\r\n", sizeof (struct HDB));
          cob = malloc_or_die ("Failed to allocate cache object memory while loading host list\r\n",
                               sizeof (struct cache));
          if (entry == NULL || cob == NULL)
               die (1, "Failed to allocate memory while loading host list");
          line[len] = (line[len] == '\n' || line[len] == '\r') ? '\0' : line[len];
          line[len - 1] = (line[len - 1] == '\n' || line[len - 1] == '\r') ? '\0' : line[len - 1];

          strncpy (entry->host, line, len);
          entry->host_hash = string_to_hash (line);
          host_to_url (LINE_LEN, redirecturl, "https://", line, "/");

          switch (type) {
          case WL:
               entry->state = REDIRECT_BW_FOUND;
               break;
          default:
          case BL:
               entry->state = REDIRECT_DENIED;
               break;
          }
          if (entry->state == REDIRECT_DENIED) {
               debug (7, "Loaded black list entry %s hash %" PRIx64 "\n", line, entry->host_hash);
          } else {
               debug (7, "Loaded white list entry %s hash %" PRIx64 "\n", line, entry->host_hash);

          }
          del_cache (entry->host_hash);
          add_cache (NULL, entry->host_hash, entry->state);

          list_add (&(entry->L), &(global.HL.L));
          ++i;
     }
}
inline int atomic_lock (int *L) {
     return __sync_val_compare_and_swap (L, 0, 1);
}

inline int atomic_unlock (int *L) {
     return __sync_val_compare_and_swap (L, 1, 0);
}
inline uint64_t string_to_hash (char *s) {
     uint64_t hash;
     unsigned int s_len = strlen (s);
     if (s == NULL || s_len < 2)
          return 0;

     crypto_auth ((unsigned char *) &hash, (const unsigned char *) s, s_len, (const unsigned char *) &global.hashkey);
     return hash;
}
void cleanup () {
     debug (5, "Exit cleanup started\r\n");
     struct list_head *lh, *tmp;
     struct cache *cob;
     struct HDB *hdbe;
     global.run = 0;
     ifdown (global.interface_in);
     ifdown (global.interface_out);
     list_for_each_safe (lh, tmp, &(global.CL.L)) {
          cob = list_entry (lh, struct cache, L);
          if (cob != NULL) {
               list_del (&(cob->L));
               free_null (cob);
          }

     }
     list_for_each_safe (lh, tmp, &(global.HL.L)) {
          hdbe = list_entry (lh, struct HDB, L);
          if (hdbe != NULL) {
               list_del (&(hdbe->L));
               free_null (hdbe);
          }

     }
     rule_purge ();
     for (; global.fdcount > 0; global.fdcount--) {
          close (global.fdlist[global.fdcount]);
     }
     debug (5, "Exit cleanup finished\r\n");
}
void compute_tcp_checksum (struct iphdr *pIph, unsigned short *ipPayload) {
     register unsigned long sum = 0;
     unsigned short tcpLen = ntohs (pIph->tot_len) - (pIph->ihl << 2);
     struct tcphdr *tcphdrp = (struct tcphdr *) (ipPayload);
     //add the pseudo header 
     //the source ip
     sum += (pIph->saddr >> 16) & 0xFFFF;
     sum += (pIph->saddr) & 0xFFFF;
     //the dest ip
     sum += (pIph->daddr >> 16) & 0xFFFF;
     sum += (pIph->daddr) & 0xFFFF;
     //protocol and reserved: 6
     sum += htons (IPPROTO_TCP);
     //the length
     sum += htons (tcpLen);

     //add the IP payload
     //initialize checksum to 0
     tcphdrp->check = 0;
     while (tcpLen > 1) {
          sum += *ipPayload++;
          tcpLen -= 2;
     }
     //if any bytes left, pad the bytes and add
     if (tcpLen > 0) {
          //printf("+++++++++++padding, %d\n", tcpLen);
          sum += ((*ipPayload) & htons (0xFF00));
     }
     //Fold 32-bit sum to 16 bits: add carrier to result
     while (sum >> 16) {
          sum = (sum & 0xffff) + (sum >> 16);
     }
     sum = ~sum;
     //set computation result
     tcphdrp->check = (unsigned short) sum;
}

/* do not use anything in this comment,moved down here pending removal --
 uint16_t ip_checksum(const void *buf, size_t hdr_len)
 {
         unsigned long sum = 0;
         const uint16_t *ip1;
 
         ip1 = buf;
         while (hdr_len > 1)
         {
                 sum += *ip1++;
                 if (sum & 0x80000000)
                         sum = (sum & 0xFFFF) + (sum >> 16);
                 hdr_len -= 2;
         }
 
         while (sum >> 16)
                 sum = (sum & 0xFFFF) + (sum >> 16);
 
         return(~sum);
 }
 inline uint16_t ip_fast_csum(const void *iph, unsigned int ihl)
 {
         unsigned int sum;
 
         asm("  movl (%1), %0\n"
             "  subl $4, %2\n"
             "  jbe 2f\n"
             "  addl 4(%1), %0\n"
             "  adcl 8(%1), %0\n"
             "  adcl 12(%1), %0\n"
             "1: adcl 16(%1), %0\n"
             "  lea 4(%1), %1\n"
             "  decl %2\n"
             "  jne      1b\n"
             "  adcl $0, %0\n"
             "  movl %0, %2\n"
             "  shrl $16, %0\n"
             "  addw %w2, %w0\n"
             "  adcl $0, %0\n"
             "  notl %0\n"
             "2:"
         // Since the input registers which are loaded with iph and ihl
            //are modified, we must also specify them as outputs, or gcc
            //will assume they contain their original values. 
             : "=r" (sum), "=r" (iph), "=r" (ihl)
             : "1" (iph), "2" (ihl)
             : "memory");
         return ( uint16_t)sum;
 }

inline unsigned short csum (unsigned short *buf, int nwords) {
     unsigned long sum;

     for (sum = 0; nwords > 0; nwords--)
          sum += *buf++;
     sum = (sum >> 16) + (sum & 0xffff);
     sum += (sum >> 16);
     return (unsigned short) (~sum);
}

*/
