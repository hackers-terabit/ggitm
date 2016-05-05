#include "util.h"

void die(int really, char *why, ...) {
        char msg[245],
         color[256] = "\033[1;31m";
        va_list arglist;

        va_start(arglist, why);

        vsnprintf(msg, 245, why, arglist);
        strncat(color, msg, 256);
        va_end(arglist);

        if (really) {

                perror(color);
                debug(4, color);
                exit(really);
        } else {
                debug(4, color);
                perror(color);
        }

}

inline void debug(int level, char *s, ...) {

        if (global.debug >= level) {
//    logg (s);
                va_list arglist;

                va_start(arglist, s);
                vprintf(s, arglist);
                va_end(arglist);
                //printf ("\n");
                fflush(stdout);

        }
}

void logg(char *s, ...) {

        va_list arglist;

        va_start(arglist, s);
        vprintf(s, arglist);
        va_end(arglist);
        printf("\n");
        fflush(stdout);
}

inline unsigned short csum(unsigned short *buf, int nwords) {
        unsigned long sum;

        for (sum = 0; nwords > 0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
}

void drop_privs() {
        int ret = 0;
        setgid(65533);
        setuid(65534);
        scmp_filter_ctx ctx;
        ctx = seccomp_init(SCMP_ACT_KILL);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, (int)SIOCGIFMTU));
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, (int)SIOCGIFINDEX));
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, (int)SIOCGIFFLAGS));

        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
        ret += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 2,
                                SCMP_A0(SCMP_CMP_EQ, 1), SCMP_A1(SCMP_CMP_EQ, 2));
        ret = seccomp_load(ctx);
        if (ret < 0)
                die(1, "Error loading SECCOMP!");
        seccomp_release(ctx);

}

void signal_handler(int signal) {

// debug (0,"\033[1;31m***********************************SIGNAL(%d) CAUGHT******************************\n"
//,signal);

        switch (signal) {
        case SIGSEGV:
                die(0xDEAD, "Of all the things I've lost I miss my mind the most.\a\n");

                break;
        case SIGKILL:
                die(0xDEAD, "KILLED !!!\n");
                break;
        case SIGCHLD:
                printf("Child process exited.\n");
                break;
        case SIGTERM:
                debug(0, "SIGTERM received. Termination signal will be sent to all threads.\n");
                global.run = 0;
                break;
        case SIGTTOU:
        case SIGPROF:
                  debug(4,"Profiling has started\n");
                break;
        default:
                die(1, "Houston We have a problem!!\n");
                return;
                break;
        }
}
void print_usage() {
        printf
            ("Usage:\nggitm  <-i interface> [-d <0-7>] [-h] [-m <il,ol,outofline,inline>] [-T https_port] [-H http_port] \n"
             "-h                           Display this help\n"
             "-d <0-7>                     Enable verbose debugging,0 is quiet,7 is noisy\n"
             "-i <interface>               specify the input interface  the application will listen on,this is a mandatory option.\n"
             "-o <interface>               specify the output interface for inline mode (mandatory for inline mode of operation)\r\n"
             "-m {inline,il,outofline,ol}  specify the mode of operation,only one mode of operation allowed.\r\n"
             "-T <1-65535>                 Specify the HTTPS port it will attempt to redirect to\r\n"
             "-H <1-65535>                 Specify the HTTP port it will attempt to intercept for redirection\r\n");
}
int parse_args(int argc, char **argv, struct global_settings *g) {
        char c;
        int debug = 4,
            h = 80,
            t = 443;
        char mode[32];
        while ((c = getopt(argc, argv, ":hd:i:o:T:H:m:")) != -1) {
                switch (c) {
                case 'd':
                        debug = atoi(optarg);
                        break;
                case 'T':
                        t = atoi(optarg);
                        break;
                case 'H':
                        h = atoi(optarg);
                        break;
                case 'm':
                        strncpy(mode, optarg, 10);
                        break;
                case 'o':
                        strncpy(global.interface_out, optarg, IFNAMSIZ);
                        break;
                case 'i':
                        strncpy(global.interface_in, optarg, IFNAMSIZ);
                        break;
                case ':':
                        print_usage();
                        die(1, "%c requires an argument!\n", optopt);
                        break;
                case 'h':
                        print_usage();
                        exit(0);
                        break;
                default:
                        print_usage();
                        die(1, "Error parsing config\n");

                }
        }
        printf("\r\n---------------------------------------------------\r\n");
        if (h < 1 || h > 65535)
                die(1, "Invalid HTTP port number");

        global.http_port = h;

        if (t < 1 || t > 65535)
                die(1, "Invalid HTTPS port number");

        global.https_port = t;

        logg("HTTP port:%i \r\nHTTPS port:%i\r\n", global.http_port, global.https_port);

        if (strlen(mode) < 2)
                strncpy(mode, "ol", 3);
        if (strncmp(mode, "inline", 6) == 0 || strncmp(mode, "il", 2) == 0) {
                global.mode = 0;
                if (strlen(global.interface_out) < 2 || strlen(global.interface_in) < 2)
                         die(1, "Invalid interfaces selected for inline mode of operation: In:%s Out:%s",
                             global.interface_in, global.interface_out);

                logg("Inline mode of operation selected.");
        } else if (strncmp(mode, "outofline", 9) == 0 || strncmp(mode, "ol", 2) == 0) {
                global.mode = 1;
                if (strlen(global.interface_in) < 2)
                         die(1, "Invalid input interface for out of line mode of operation: %s", global.interface_in);

                logg("Out of line mode of operation selected.");

        }

        logg("Input interface %s\r\nOutput interface %s\r\n", global.interface_in, global.interface_out);

        global.debug = debug;
        logg("Debug level set to %i\r\n", global.debug);
        printf("\r\n---------------------------------------------------\r\n");
        return 0;
}
void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
        register unsigned long sum = 0;
        unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl << 2);
        struct tcphdr *tcphdrp = (struct tcphdr *)(ipPayload);
        //add the pseudo header 
        //the source ip
        sum += (pIph->saddr >> 16) & 0xFFFF;
        sum += (pIph->saddr) & 0xFFFF;
        //the dest ip
        sum += (pIph->daddr >> 16) & 0xFFFF;
        sum += (pIph->daddr) & 0xFFFF;
        //protocol and reserved: 6
        sum += htons(IPPROTO_TCP);
        //the length
        sum += htons(tcpLen);

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
                sum += ((*ipPayload) & htons(0xFF00));
        }
        //Fold 32-bit sum to 16 bits: add carrier to result
        while (sum >> 16) {
                sum = (sum & 0xffff) + (sum >> 16);
        }
        sum = ~sum;
        //set computation result
        tcphdrp->check = (unsigned short)sum;
}
