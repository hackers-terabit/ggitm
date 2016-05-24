
#include "ggitm.h"
#include "util.h"

#define _GNU_SOURCE
void http_dump (struct PKT *pkt) {
     int i = 0;
     printf ("\n--------------------------------------------\n");

     for (i = 0; i < pkt->datalen; i++) {
          printf ("%c", pkt->data[i]);
     }
     printf ("\n--------------------------------------------\n");

}

inline int get_http_host (char *data, char *buf, int bufsz) {
     char c;
     int i = 0;
     if (isnull (data) || isnull_ (data))
          return 0;
     char *s = strcasestr ((char *) data, "host:");

     if (s == NULL || (strlen (s) < 6))
          return 0;
     else {
          s = &s[6];
          for (i = 0; i < bufsz && i < HEADER_DEPTH; i++) {
               c = s[i];
               if (c == ':' || c == '\r' || c == '\n' || c == '\0' || (!isprint (c)))
                    break;
               else
                    buf[i] = c;
          }
          if (i < 3)
               return 0;

          return 1;
     }
     return 0;
}

inline int get_http_request (char *data, char *buf, int bufsz) {
     char c;
     int i = 0, o;
     if (isnull (data) || isnull_ (data))
          return 0;
     char *get = strcasestr ((char *) data, "GET ");
     char *head = strcasestr ((char *) data, "HEAD ");

     if (get == NULL || (strlen (get) < 5)) {
          if (head == NULL || (strlen (head) < 6))
               return 0;
          else {
               get = head;
               o = 5;
          }
     } else
          o = 4;

     get = &get[o];
     for (i = 0; i < bufsz - 1 && i < HEADER_DEPTH; i++) {
          c = get[i];
          if (c == ' ' || c == '\r' || c == '\n' || c == '\0' || (!isprint (c)))
               break;
          else
               buf[i] = c;
     }
     buf[i + 1] = '\0';

     return 1;

}
inline struct cache *search_cache (uint64_t uhash) {

     struct list_head *lh, *tmp;
     struct cache *entry;
     debug (5, "Cache lookup for url hash %" PRIx64 "\r\n", uhash);
     while (!atomic_lock (&global.cache_lock));

     list_for_each_safe (lh, tmp, &(global.CL.L)) {
          entry = list_entry (lh, struct cache, L);
          if (entry != NULL) {
               //  debug (7, "%" PRIx64 " <-> %" PRIx64 "\r\n", uhash, entry->match_url);
               if (entry->match_url == uhash) {
                    atomic_unlock (&global.cache_lock);
                    return entry;
               }
          }

     }
     atomic_unlock (&global.cache_lock);

     return NULL;
}
inline void add_cache (char *url, uint64_t match_hash, int response) {

     struct cache *cob =
          malloc_or_die ("malloc() failure when adding an entry to the global cache\r\n", sizeof (struct cache));

     int url_len;
     if (url != NULL)
          url_len = strlen (url);

     memset (cob, 0, sizeof (struct cache));
     cob->response = response;
     cob->match_url = match_hash;
     if (url != NULL)
          memcpy (cob->redirect_url, url, url_len);
     else
          memset (cob->redirect_url, 0, URL_MAX);

     while (!atomic_lock (&global.cache_lock));

     list_add (&(cob->L), &(global.CL.L));
     atomic_unlock (&global.cache_lock);
}
inline void del_cache (uint64_t hash) {
     // struct list_head *lh, *tmp;
     struct cache *entry, *clh, *ctmp;
     // debug (7, "Deleting cache entries that match hash %" PRIx64 "\r\n", hash);
     while (!atomic_lock (&global.cache_lock));
     if (list_empty (&(global.CL.L))) {
          atomic_unlock (&global.cache_lock);
          return;
     }
     list_for_each_entry_safe (clh, ctmp, &(global.CL.L), L) {
          entry = list_entry (clh, struct cache, L);
          if (entry != NULL) {
               if (entry->match_url == hash) {
                    list_del (&(entry->L));
                    if (entry != NULL)
                         free_null (entry);
               }
          }
     }
     atomic_unlock (&global.cache_lock);

}
int http_packet (struct traffic_context tcx) {
     int hlen = tcx.pkt->datalen < HEADER_DEPTH ? tcx.pkt->datalen : HEADER_DEPTH - 1, state = REDIRECT_DENIED;
     char host[hlen];
     char request[hlen];
     char assumed_url[hlen];
     char url_https[hlen];

     uint64_t match_hash, host_hash;
     struct cache *cob;

     memset (host, 0, hlen);
     memset (request, 0, hlen);
     memset (assumed_url, 0, hlen);
     memset (url_https, 0, hlen);

     if (get_http_host ((char *) tcx.pkt->data, host, hlen) && get_http_request ((char *) tcx.pkt->data, request, hlen)) {
          //this is to make it easier to read debug outputs for debug levels 5 and above
       	       kill_session_server(tcx);

          debug (5, "\r\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\r\n");
          debug (4, "TCP seq: %x<>%x - HTTP host header found: --%s-- request |%s|\r\n",
                 ntohl (tcx.pkt->tcpheader->seq), ntohl (tcx.pkt->tcpheader->ack_seq), host, request);

          host_to_url (hlen, assumed_url, "http://", host, request);
          host_to_url (hlen, url_https, "https://", host, request);
          debug (6, "NEW_HTTPS %s\r\n", url_https);
          match_hash = string_to_hash (assumed_url);
          host_hash = string_to_hash (host);

          if (!match_hash)
               die (0, "Warning,string to hash conversion has failed with a 0,string %s\r\n", assumed_url);

          cob = search_cache (match_hash);      //do  a full host+request search
          if (cob != NULL) {
               if (cob->response == REDIRECT_RULE_FOUND) {
                    send_response (tcx, host, request, cob->redirect_url, 301);
                    kill_session (tcx);
                    debug (4, "REDIRECT_CACHE_HIT  [1] for host %s , request=%s ; newurl=%s; 301_REDIRECT_SENT\n", host,
                           request, cob->redirect_url);
                    return 0;
               } else if (cob->response == REDIRECT_DENIED) {
                    debug (4, "REDIRECT_CACHE_HIT [2] for host %s , request=%s ; REDIRECT_DENIED!\n", host, request);
                    return global.failmode;
               } else if (cob->response == REDIRECT_BW_FOUND) {
                    send_response (tcx, host, request, url_https, 301);
                    kill_session (tcx);
                    debug (4, "REDIRECT_CACHE_HIT [3] BW for host %s , request=%s ; newurl=%s\n", host, request,
                           url_https);
                    return 0;
               }
          } else {              //full host+request no match 
               cob = search_cache (host_hash);
               if (cob != NULL) {       //REDIRECT_CACHE_HIT
                    if (cob->response == REDIRECT_RULE_FOUND || cob->response == REDIRECT_BW_FOUND) {

                         send_response (tcx, host, request, url_https, 301);
                         kill_session (tcx);
                         debug (4, "REDIRECT_CACHE_HIT [4] for host %s ; newurl=%s; 301_REDIRECT_SENT\n", host,
                                url_https);
                         return 0;
                    } else {
                         debug (4, "REDIRECT_CACHE_HIT [5] for host %s ; newurl=%s ; REDIRECT_DENIED\n", host,
                                url_https);
                         return global.failmode;
                    }
               } else {         //REDIRECT_CACHE_MISS
                    debug (4, "REDIRECT_CACHE_MISS for just the host part of the request %s \r\n", host);
               }
               kill_session (tcx);
	       kill_session_server(tcx);
               if (global.mode == IL) {

                    rule_search (assumed_url, host);
                    debug (4, "REDIRECT_CACHE_MISS sent a refresh page  response for host %s , request=%s ; url=%s\n",
                           host, request, assumed_url);
               } else if (global.mode == OL) {
                    check_redirect (url_https, &state);
                    del_cache (host_hash);
                    add_cache (url_https, host_hash, state);

               }
               return global.failmode;
          }

     }

     return global.failmode;
}
void fill_payload (char *response_payload, char *host, char *url, char *request, int type) {
     //bah! a lot of this could probably be offloaded to a macro or something,we should use constant vars,etc...
     //PAYLOAD: print response  
     if (url == NULL) {
          if (type == 301)
               xprintf (response_payload, HEADER_DEPTH - 1, "HTTP/1.1 301 Moved Permanently\r\n"
                        "Location: https://%s/%s\r\n" "X-MITM-ATTACKER: Good-guy-in-the-middle\r\n", host, request);
          if (type == 302)
               xprintf (response_payload, HEADER_DEPTH - 1, "HTTP/1.1 302 Found\r\n"
                        "Location: https://%s/%s\r\n" "X-MITM-ATTACKER: Good-guy-in-the-middle\r\n", host, request);
     } else {
          if (type == 301)
               xprintf (response_payload, HEADER_DEPTH - 1, "HTTP/1.1 301 Moved Permanently\r\n"
                        "Location: %s\r\n" "X-MITM-ATTACKER: Good-guy-in-the-middle\r\n", url);
          if (type == 302)
               xprintf (response_payload, HEADER_DEPTH - 1, "HTTP/1.1 302 Found\r\n"
                        "Location: %s\r\n" "X-MITM-ATTACKER: Good-guy-in-the-middle\r\n", url);
     }
}
void send_response (struct traffic_context tcx, char *host, char *request, char *url, int type) {
     struct PKT newpacket;
     struct ethh *eh;
     char *response_payload = malloc_or_die ("Error allocating memory for a response payload\r\n", HEADER_DEPTH);
     memset (response_payload, 0, HEADER_DEPTH);
     int i = 0, response_length, bytes;
     uint8_t TCPHDR = sizeof (struct tcphdr);
     //fill_payload (response_payload, host, url, request, type);
     xprintf (response_payload, HEADER_DEPTH - 1, "HTTP/1.1 301 Moved Permanently\r\n"
              "Location: https://%s/%s\r\n" "X-MITM-ATTACKER: Good-guy-in-the-middle\r\n", host, request);

     response_length = strlen (response_payload);
     //allocate memory,point the pointers...
     newpacket.ethernet_frame =
          malloc_or_die ("Error, allocating %i bytes failed in send_response", tcx.pkt->mtu, tcx.pkt->mtu);
     if (tcx.pkt->len <= (ETHIP4 + TCPHDR)) {
          debug (6, "Received an http packet with no payload");
          free_null (response_payload);
          return;
     }
     newpacket.data = (uint8_t *) newpacket.ethernet_frame + (ETHIP4 + TCPHDR);
     response_length =
          response_length < (tcx.pkt->mtu - (ETHIP4 + TCPHDR)) ? response_length : (tcx.pkt->mtu - (ETHIP4 + TCPHDR));
     memcpy (newpacket.data, response_payload, response_length);
     newpacket.ipheader = (struct iphdr *) (newpacket.ethernet_frame + ETH_HDRLEN);
     newpacket.tcpheader = (struct tcphdr *) (newpacket.ethernet_frame + ETHIP4);
     //TCP:
     newpacket.tcpheader->window = tcx.pkt->tcpheader->window;  //don't really care about window sinc we don't care about the fate of this connection
     newpacket.tcpheader->ack = 1;
     newpacket.tcpheader->syn = 0;
     newpacket.tcpheader->fin = 0;
     newpacket.tcpheader->rst = 0;
     newpacket.tcpheader->source = tcx.pkt->tcpheader->dest;
     newpacket.tcpheader->dest = tcx.pkt->tcpheader->source;
     newpacket.tcpheader->seq = tcx.pkt->tcpheader->ack_seq;
     newpacket.tcpheader->ack_seq = htonl (tcx.pkt->datalen + ntohl (tcx.pkt->tcpheader->seq)); //our response needs to ack the request, we can do a separate ack
     //which is what grack() was about,but it seems we don't really need it

     newpacket.tcpheader->doff = (TCPHDR / 4);  //our response will always be this size,so no need to calculate header length

     //IPv4:
     memcpy (newpacket.ipheader, tcx.pkt->ipheader, IP4_HDRLEN);
     newpacket.ipheader->daddr = tcx.pkt->ipheader->saddr;
     newpacket.ipheader->saddr = tcx.pkt->ipheader->daddr;
     newpacket.ipheader->tot_len = htons (IP4_HDRLEN + TCPHDR + response_length);
     newpacket.ipheader->check = IPV4CalculateChecksum ((uint16_t *) newpacket.ipheader, IP4_HDRLEN);

     //ETHERNET:
     eh = (struct ethh *) newpacket.ethernet_frame;
     memcpy (newpacket.ethernet_frame, &tcx.pkt->ethernet_frame[6], 6); //old src mac -> new dst mac
     memcpy (&newpacket.ethernet_frame[6], tcx.pkt->ethernet_frame, 6); //old dst mac -> new src mac
     eh->ethtype = htons (ETH_P_IP);

     compute_tcp_checksum (newpacket.ipheader, (uint16_t *) newpacket.tcpheader);

     for (i = 0; i < 3; i++) {  //not leaving it to chance , send the redirect 3 times in case the first is lost and a retransmit is needed
          // in which case the 200/ok might make it fine and the redirect attempt fails.
          bytes = write (tcx.fd_in, newpacket.ethernet_frame, response_length + (ETHIP4 + TCPHDR));     /* (tcx.fd_in, newpacket.ethernet_frame,
                                                                                                           response_length + (ETHIP4 + TCPHDR), 0, (struct sockaddr *) &tcx.sll_in,
                                                                                                           sizeof (struct sockaddr_ll)); */
          if (bytes < (response_length + (ETHIP4 + TCPHDR)))
               break;
     }
     if (bytes == (response_length + (ETHIP4 + TCPHDR))) {
          newpacket.len = bytes;
          trace_dump ("301 redirect ", &newpacket);
     } else
          die (0, "Error sending 301");
     free_null (newpacket.ethernet_frame);
     free_null (response_payload);

}
void kill_session (struct traffic_context tcx) {
     struct PKT newpacket;
     struct ethh *eh;
     char response_payload[HEADER_DEPTH];
     memset (response_payload, 0, HEADER_DEPTH);
     int i = 0, response_length, bytes;
     uint8_t TCPHDR = sizeof (struct tcphdr);
     xprintf (response_payload, 10, "");
     response_length = strlen (response_payload);
     newpacket.ethernet_frame =
          malloc_or_die ("Error, allocating %i bytes failed in kill_session", tcx.pkt->mtu, tcx.pkt->mtu);
     if (tcx.pkt->len <= (ETHIP4 + TCPHDR)) {
          debug (6, "kill_session() received an tcp packet with no payload");
          return;
     }
     newpacket.data = (uint8_t *) newpacket.ethernet_frame + (ETHIP4 + TCPHDR);
     memset (newpacket.ethernet_frame, 0, tcx.pkt->mtu);
     response_length =
          response_length < (tcx.pkt->mtu - (ETHIP4 + TCPHDR)) ? response_length : (tcx.pkt->mtu - (ETHIP4 + TCPHDR));
     memcpy (newpacket.data, response_payload, response_length);
     newpacket.ipheader = (struct iphdr *) (newpacket.ethernet_frame + ETH_HDRLEN);
     newpacket.tcpheader = (struct tcphdr *) (newpacket.ethernet_frame + ETHIP4);
     //TCP:
     newpacket.tcpheader->window = tcx.pkt->tcpheader->window;  //don't really care about window sinc we don't care about the fate of this connection
     newpacket.tcpheader->ack = 1;
     newpacket.tcpheader->rst = 1;
     newpacket.tcpheader->source = tcx.pkt->tcpheader->dest;
     newpacket.tcpheader->dest = tcx.pkt->tcpheader->source;
     newpacket.tcpheader->seq = htonl (1 + ntohl (tcx.pkt->tcpheader->ack_seq));
     newpacket.tcpheader->ack_seq = htonl (tcx.pkt->datalen + ntohl (tcx.pkt->tcpheader->seq)); //our response needs to ack the request, we can do a separate ack
     newpacket.tcpheader->doff = (TCPHDR / 4);  //our response will always be this size,so no need to calculate header length
     //IPv4:
     memcpy (newpacket.ipheader, tcx.pkt->ipheader, IP4_HDRLEN);
     newpacket.ipheader->daddr = tcx.pkt->ipheader->saddr;
     newpacket.ipheader->saddr = tcx.pkt->ipheader->daddr;
     newpacket.ipheader->tot_len = htons (IP4_HDRLEN + TCPHDR + response_length);
     newpacket.ipheader->check = IPV4CalculateChecksum ((unsigned short *) newpacket.ipheader, IP4_HDRLEN);
     //ETHERNET:
     eh = (struct ethh *) newpacket.ethernet_frame;
     memcpy (newpacket.ethernet_frame, &tcx.pkt->ethernet_frame[6], 6); //old src mac -> new dst mac
     memcpy (&newpacket.ethernet_frame[6], tcx.pkt->ethernet_frame, 6); //old dst mac -> new src mac
     eh->ethtype = htons (ETH_P_IP);
     compute_tcp_checksum (newpacket.ipheader, (unsigned short *) newpacket.tcpheader);
     for (i = 0; i < 3; i++) {  //not leaving it to chance , send the redirect 3 times in case the first is lost and a retransmit is needed
          bytes = sendto (tcx.fd_in, newpacket.ethernet_frame,
                          response_length + (ETHIP4 + TCPHDR), 0, (struct sockaddr *) &tcx.sll_in,
                          sizeof (struct sockaddr_ll));
     }
     if (bytes > 0) {
          newpacket.len = bytes;
          trace_dump ("client kill ", &newpacket);
     } else
          die (0, "\r\nError sending Client kill");
     free_null (newpacket.ethernet_frame);
}
void kill_session_server (struct traffic_context tcx) {
     struct PKT newpacket;
     struct ethh *eh;
     char response_payload[HEADER_DEPTH];
     memset (response_payload, 0, HEADER_DEPTH);

     int i = 0, response_length, bytes;
     uint8_t TCPHDR = sizeof (struct tcphdr);
     xprintf (response_payload, 10, "");
     response_length = strlen (response_payload);
     //allocate memory,point the pointers...
     newpacket.ethernet_frame =
          malloc_or_die ("Error, allocating %i bytes failed in kill_session_server", tcx.pkt->mtu, tcx.pkt->mtu);
     if (tcx.pkt->len <= (ETHIP4 + TCPHDR)) {
          debug (6, "kill_session() received an tcp packet with no payload");
          return;
     }
     newpacket.data = (uint8_t *) newpacket.ethernet_frame + (ETHIP4 + TCPHDR);
     memset (newpacket.ethernet_frame, 0, tcx.pkt->mtu);
     response_length =
          response_length < (tcx.pkt->mtu - (ETHIP4 + TCPHDR)) ? response_length : (tcx.pkt->mtu - (ETHIP4 + TCPHDR));
     memcpy (newpacket.data, response_payload, response_length);
     newpacket.ipheader = (struct iphdr *) (newpacket.ethernet_frame + ETH_HDRLEN);
     newpacket.tcpheader = (struct tcphdr *) (newpacket.ethernet_frame + ETHIP4);
     if (global.mode == IL) {
          memset (newpacket.ethernet_frame, 0, tcx.pkt->mtu);
          //TCP:
          newpacket.tcpheader->window = tcx.pkt->tcpheader->window;
          newpacket.tcpheader->rst = 1;
          newpacket.tcpheader->source = tcx.pkt->tcpheader->source;
          newpacket.tcpheader->dest = tcx.pkt->tcpheader->dest;
          newpacket.tcpheader->seq = tcx.pkt->tcpheader->seq;
          newpacket.tcpheader->ack_seq = tcx.pkt->tcpheader->ack_seq;
          newpacket.tcpheader->doff = (TCPHDR / 4);     //our response will always be this size,so no need to calculate header length
          //IPv4:
          memcpy (newpacket.ipheader, tcx.pkt->ipheader, IP4_HDRLEN);
          newpacket.ipheader->tot_len = htons (IP4_HDRLEN + TCPHDR + response_length);
          newpacket.ipheader->check = IPV4CalculateChecksum ((unsigned short *) newpacket.ipheader, IP4_HDRLEN / 4);
          debug (5, "newpacket checksum set to %0x\r\n", newpacket.ipheader->check);
          //ETHERNET:
          eh = (struct ethh *) newpacket.ethernet_frame;
          memcpy (newpacket.ethernet_frame, tcx.pkt->ethernet_frame, 12);
          eh->ethtype = htons (ETH_P_IP);

          compute_tcp_checksum (newpacket.ipheader, (unsigned short *) newpacket.tcpheader);
          for (i = 0; i < 3; i++) {     //not leaving it to chance , send the redirect 3 times in case the first is lost and a retransmit is needed
               bytes = sendto (tcx.fd_in, newpacket.ethernet_frame,
                               response_length + (ETHIP4 + TCPHDR), 0, (struct sockaddr *) &tcx.sll_in,
                               sizeof (struct sockaddr_ll));
          }
          if (bytes > 0) {
               newpacket.len = bytes;
               trace_dump ("server kill ", &newpacket);
          } else
               die (0, "Error sending Server kill");
     }
     free_null (newpacket.ethernet_frame);
}

int redirect_ok (char *host, char *url, char **redirect_url) {
     struct list_head *lh;
     struct rules *rule;
     int res, i, ovec[256];
     size_t reslen;
     while (!atomic_lock (&global.lookup_lock));

     list_for_each (lh, &(global.RL.L)) {       //httpseverywhere compatible pcre rule lookup
          rule = list_entry (lh, struct rules, L);
          if (rule != NULL) {
               for (i = 0; i < rule->target_count && i < MAX_REGEX; i++) {
                    res = pcre_exec (rule->targets[i], 0, host, strlen (host), 0, 0, ovec, 256);

                    if (res < 0) {
                         switch (res) {
                         case PCRE_ERROR_NOMATCH:
                              debug (7, "Match failed host:%s,rule:%s\r\n", host, rule->name);
                              break;

                         default:
                              debug (7, "Error while matching host to target - host:%s,rule:%s\r\n", host, rule->name);
                              break;
                         }
                    } else {    //host matches target!
                         debug (6, "Host %s matches rule %s\r\n", host, rule->name);
                         res = pcrs_execute (rule->job, url, strlen (url), redirect_url, &reslen);
                         if (res < 1) {

                              debug (6, "Error matching host:%s , url:%s with pcrs\r\n", host, url);
                              atomic_unlock (&global.lookup_lock);

                              return REDIRECT_DENIED;
                         } else if (res > 0) {
                              atomic_unlock (&global.lookup_lock);

                              return REDIRECT_RULE_FOUND;
                         }
                         break;
                    }

               }
          }
     }

     atomic_unlock (&global.lookup_lock);

     return REDIRECT_DENIED;
}

void rule_search (char *url, char *host) {
     struct timeval before, after, result;
     int res;
     char *newurl;
     if (url == NULL || host == NULL || strlen (url) < 1 || strlen (host) < 1) {
          die (0, "rule_search with an empty host or url attempted!");
          return;
     }
     uint64_t hash = string_to_hash (url);

     debug (5, "Rule search thread started for hash:%" PRIx64 " ; url: %s \r\n", hash, url);
     if (global.debug > 4) {
          gettimeofday (&before, NULL);
          res = redirect_ok (host, url, &newurl);
          gettimeofday (&after, NULL);
          timersub (&after, &before, &result);

          debug (4, "It took %i micro seconds for redirect_ok to complete\n", result.tv_usec);
     } else {
          res = redirect_ok (host, url, &newurl);

     }
     if (res == REDIRECT_RULE_FOUND) {
          check_redirect (newurl, &res);
          del_cache (hash);
          add_cache (newurl, hash, res);
          debug (5, "REDIRECT_RULE_FOUND adding %s for url %s hash %" PRIx64 "\r\n", newurl, url, hash);
     } else {
          del_cache (hash);
          add_cache (NULL, hash, res);
          debug (5, "REDIRECT_DENIED,adding a denied entry for url: %s hash %" PRIx64 "\r\n", url, hash);
     }
     debug (5, "Rule search thread finished for url: %s\r\n", url);

}
void curl_opts (CURL * curl, char *url) {
     curl_easy_setopt (curl, CURLOPT_URL, url);
     curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1);
     curl_easy_setopt (curl, CURLOPT_NOBODY, 1);
     curl_easy_setopt (curl, CURLOPT_TIMEOUT, 5L);
     curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 1L);
     curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 2L);
     curl_easy_setopt (curl, CURLOPT_USERAGENT, global.UA);
     if (global.debug > 5)
          curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);
}
void check_redirect (char *url, int *state) {
     while (!atomic_lock (&global.curl_lock));

     //fwiw, I copy pasted the curlish parts of this from their examples page
     CURL *curl;
     CURLcode res=0;
     char *location;
     unsigned int response_code;

     curl = curl_easy_init ();
     if (curl) {
          curl_opts (curl, url);
          res = curl_easy_perform (curl);
          if (res == CURLE_OK) {
               res = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
               debug (6, "Response code %i for url %s \n", response_code, url);
               if (res == CURLE_OK) {
                    if (response_code == 301 || response_code == 302) {
                         res = curl_easy_getinfo (curl, CURLINFO_REDIRECT_URL, &location);
                         if ((res == CURLE_OK) && location && strlen (location) > 7) {
                              if (strncasecmp ("http://", location, 7) == 0) {
                                   *state = REDIRECT_DENIED;    //the server is listening on https but redirecting us back to an http url 
                                   debug (6,
                                          "301 or 302 redirect for the https url %s returning a http URL %s,marking url as REDIRECT_DENIED\n",
                                          url, location);
                              } else {
                                   *state = REDIRECT_RULE_FOUND;
                              }
                         }
                    } else {
                         *state = REDIRECT_RULE_FOUND;
                    }
               } else {
                    *state = REDIRECT_DENIED;   //unable to get a response code over HTTPS
               }
          } else {
               *state = REDIRECT_DENIED;        //unable to curl the https url
          }

     }
     curl_easy_cleanup (curl);

     atomic_unlock (&global.curl_lock);
}
