#ifndef MACROS_H

#define IFINDEX 0
#define IFMTU 1
#define IFMAC 2
#define IFADDR 3

//ethernet and arp ...
#define ETH_HDRLEN 14
#define IP4_HDRLEN 20
#define ARP_HDRLEN 28
#define ARP_TIMEOUT 5
#define ETHIP4 IP4_HDRLEN + ETH_HDRLEN

#define COMMENT_CHAR '#'
#define LINE_LEN 256
#define WL 5500
#define BL 5511
#define OL 1                    //out of line
#define IL 0                    // in line

#define HEADER_DEPTH 1200        // how many bytes into any packet's payload we'll look
#define URL_MAX 2000            // MS/IE have this at 2083,just to round it out since we may add / to the end in the response
#define CACHE_MAX 100000        // 100k cache entries by default
#define REDIRECT_MAX 9          //after 9 bogus redirects we will direct them back to their original host
#define FD_MAX 10000

#define REDIRECT_BW_FOUND 200   //BWL == black white list
#define REDIRECT_RULE_FOUND 300
#define REDIRECT_NEW  400
#define REDIRECT_EXPIRED 500
#define REDIRECT_DENIED 789

#define MAX_REGEX 2048          //20000 regex's per regex array, a bit high,had to bump it up from 2048 thanks to bit.ly


#define TMAX 4096


#ifndef PACKET_FANOUT
#define PACKET_FANOUT                  18
#define PACKET_FANOUT_HASH             0
#define PACKET_FANOUT_LB               1
#endif


#endif 