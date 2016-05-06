
#include "ggitm.h"
#define _GNU_SOURCE
void http_dump (struct PKT *httppacket) {
  int i = 0;
  printf ("\n--------------------------------------------\n");

  for (i; i < httppacket->datalen; i++) {
    printf ("%c", httppacket->data[i]);
  }
  printf ("\n--------------------------------------------\n");

}

inline int get_http_host (uint8_t * data, char *buf, int bufsz) {
  char *tmp,
   *tmp2,
    c;
  int n = 0,
    i = 0;
  char *s = strcasestr ((char *) data, "host:");

  if (s == NULL || (strlen (s) < 6))
    return 0;
  else {
    s = &s[6];
    for (i; i < bufsz; i++) {
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

inline int get_http_request (uint8_t * data, char *buf, int bufsz) {
  char *tmp,
   *tmp2,
    c;
  int n = 0,
    i = 0,o;
  char *get = strcasestr ((char *) data, "GET ");
  char *head = strcasestr ((char *) data, "HEAD ");

  if (get == NULL || (strlen (get) < 6)){
  if (head == NULL || (strlen (head) < 6))
    return 0;
  else {
    get=head;
    o=5;
  }
  }else o=4;
  
  
    get = &get[o];
    for (i; i < bufsz-1; i++) {
      c = get[i];
      if (c == ' ' || c == '\r' || c == '\n' || c == '\0' || (!isprint (c)))
        break;
      else
        buf[i] = c;
    }
   buf[i+1]='\0';

    return 1;
 
}

void http_packet (struct PKT *httppacket) {
  int hlen = httppacket->datalen < HEADER_DEPTH ? httppacket->datalen : HEADER_DEPTH - 1;
  int res;
  char host[hlen];
  char request[hlen];
  struct timeval before,
    after,
    result;

  memset (host, 0, hlen);
  if (get_http_host (httppacket->data, host, hlen) && get_http_request(httppacket->data,request,hlen)) {
    debug (4, "TCP seq: %x<>%x - HTTP host header found: --%s-- request |%s|\r\n", ntohl (httppacket->tcpheader->seq),
           ntohl (httppacket->tcpheader->ack_seq), host,request);
    if (global.debug > 4) {
      gettimeofday (&before, NULL);
      res = redirect_ok (host);
      gettimeofday (&after, NULL);
      timersub (&after, &before, &result);

      debug (4, "It took %i micro seconds for redirect_ok to complete\n", result.tv_usec);
    } else {
      res = redirect_ok (host);

    }
    if (res == REDIRECT_FOUND) {
      send_response (httppacket, host,request,301);
      debug (6, "REDIRECT_FOUND for host %s\n", host);
    } else if (res == REDIRECT_NEW) {
      //we're not sure this will work for the user
      //that's why we're using a 302,so the browser or client
      //does not cache the redirection in the event it's a failure
      //REDIRECT_FOUND above means we know for sure https works
      //so we're giving them a 301, unlike here:
      send_response (httppacket, host,request,302); 
      check_redirect (host);
      debug (6, "REDIRECT_NEW for host %s\n", host);

    } else if (res == REDIRECT_EXPIRED) {
      //this is a place holder if we want to age out redirections.
    } else if (res == REDIRECT_DENIED) {
      debug (6, "HTTPS redirect to host %s has been denied\n", host);
      return;
    }

  }
}

void send_response (struct PKT *pkt, char *host , char *request,int type ) {
  struct PKT newpacket;
  struct sockaddr_ll sll;
  struct ethh *eh;
  char response_payload[HEADER_DEPTH],str_302[HEADER_DEPTH];
  memset (response_payload, 0, HEADER_DEPTH);
  
  int i = 0,
    pktlen,
    response_length,
    bytes;
  uint8_t TCPHDR = sizeof (struct tcphdr);


  //PAYLOAD: print response  
if(type==301)
  snprintf (response_payload, HEADER_DEPTH - 1, "HTTP/1.1 301 Moved Permanently\r\n"
                                                "Location: https://%s/%s\r\n" 
						"X-MITM-ATTACKER: Good-guy-in-the-middle\r\n"
						, host,request);
if(type==302)
  snprintf (response_payload, HEADER_DEPTH - 1, "HTTP/1.1 302 Found\r\n"
                                                "Location: https://%s/%s\r\n" 
	                                        "X-MITM-ATTACKER: Good-guy-in-the-middle\r\n"
	                                         , host,request);  
  
  response_length = strlen (response_payload);
  //allocate memory,point the pointers...
  newpacket.ethernet_frame = malloc (pkt->mtu);
  if (newpacket.ethernet_frame == NULL) {
    debug (2, "Error, allocating %i bytes failed in send_response", pkt->mtu);
    return;
  }
  if (pkt->len <= (ETHIP4 + TCPHDR)) {
    debug (6, "Received an http packet with no payload");
    return;
  }
  newpacket.data = (uint8_t *) newpacket.ethernet_frame + (ETHIP4 + TCPHDR);
  memset (newpacket.ethernet_frame, 0, pkt->mtu);
  response_length = response_length < (pkt->mtu - (ETHIP4 + TCPHDR)) ? response_length : (pkt->mtu - (ETHIP4 + TCPHDR));
  memcpy (newpacket.data, response_payload, response_length);
  newpacket.ipheader = (struct iphdr *) (newpacket.ethernet_frame + ETH_HDRLEN);
  newpacket.tcpheader = (struct tcphdr *) (newpacket.ethernet_frame + ETHIP4);

  //  pktlen = ntohs(pkt->ipheader->tot_len) - (IP4_HDRLEN + sizeof (struct tcphdr)); //this will break if tcp/ip header length is non-default,needs to be fixed //TODO
  //TCP:
  newpacket.tcpheader->window = pkt->tcpheader->window; //don't really care about window sinc we don't care about the fate of this connection
  newpacket.tcpheader->ack = 1;
  newpacket.tcpheader->syn = 0;
  newpacket.tcpheader->fin = 0;
  newpacket.tcpheader->rst = 0;
  newpacket.tcpheader->source = pkt->tcpheader->dest;
  newpacket.tcpheader->dest = pkt->tcpheader->source;
  newpacket.tcpheader->seq = pkt->tcpheader->ack_seq;
  newpacket.tcpheader->ack_seq = htonl (pkt->datalen + ntohl (pkt->tcpheader->seq));    //our response needs to ack the request, we can do a separate ack
  //which is what grack() was about,but it seems we don't really need it

  newpacket.tcpheader->doff = (TCPHDR / 4);     //our response will always be this size,so no need to calculate header length

  //IPv4:
  memcpy (newpacket.ipheader, pkt->ipheader, IP4_HDRLEN);
  newpacket.ipheader->daddr = pkt->ipheader->saddr;
  newpacket.ipheader->saddr = pkt->ipheader->daddr;
  newpacket.ipheader->tot_len = htons (IP4_HDRLEN + TCPHDR + response_length);
  newpacket.ipheader->check = csum ((unsigned short *) newpacket.ipheader, IP4_HDRLEN);

  //ETHERNET:
  eh = (struct ethh *) newpacket.ethernet_frame;
  memcpy (newpacket.ethernet_frame, &pkt->ethernet_frame[6], 6);        //old src mac -> new dst mac
  memcpy (&newpacket.ethernet_frame[6], pkt->ethernet_frame, 6);        //old dst mac -> new src mac
  eh->ethtype = htons (ETH_P_IP);

  compute_tcp_checksum (newpacket.ipheader, (unsigned short *) newpacket.tcpheader);
  for (i; i < 3; i++) {         //not leaving it to chance , send the redirect 3 times in case the first is lost and a retransmit is needed
    // in which case the 200/ok might make it fine and the redirect attempt fails.
    bytes = sendto (global.af_socket, newpacket.ethernet_frame,
                    response_length + (ETHIP4 + TCPHDR), 0, (struct sockaddr *) &global.sll, sizeof (global.sll));

  }

  if (bytes > 0) {
    newpacket.len = bytes;
    trace_dump ("301 redirect ", &newpacket);
  } else
    die (0, "Error sending 301");

  free (newpacket.ethernet_frame);

}
void kill_session (struct PKT *pkt) {

}
void grack (struct PKT *pkt) {
//         struct PKT newpacket;
//         struct sockaddr_ll sll;
// 
//         int pktlen,
//          bytes;
// 
//         pktlen = ntohs(pkt->ipheader->tot_len) - (IP4_HDRLEN + sizeof (struct tcphdr)); //this will break if tcp/ip header length is non-default,needs to be fixed //TODO
//         newpacket.ethernet_frame = malloc(pkt->mtu);
//         newpacket.data = (uint8_t *) newpacket.ethernet_frame + (ETHIP4 + sizeof (struct tcphdr));
// 
//         memset(newpacket.ethernet_frame, 0, pkt->mtu);
// 
//         newpacket.ipheader = (struct iphdr *)(newpacket.ethernet_frame + ETH_HDRLEN);
//         newpacket.tcpheader = (struct tcphdr *)(newpacket.ethernet_frame + ETHIP4);
// 
//         memcpy(newpacket.ethernet_frame, &pkt->ethernet_frame[6], 6);   //old src mac -> new dst mac
//         memcpy(&newpacket.ethernet_frame[6], pkt->ethernet_frame, 6);   //old dst mac -> new src mac
// 
//         memcpy(newpacket.ipheader, pkt->ipheader, IP4_HDRLEN);
//         newpacket.ipheader->daddr = pkt->ipheader->saddr;
//         newpacket.ipheader->saddr = pkt->ipheader->daddr;
//         newpacket.ipheader->tot_len = htonl(IP4_HDRLEN + sizeof (struct tcphdr));
//         newpacket.ipheader->check = csum((unsigned short *)newpacket.ipheader, IP4_HDRLEN);
// 
//         newpacket.tcpheader->window = pkt->tcpheader->window;
//         newpacket.tcpheader->ack = 1;
//         newpacket.tcpheader->source = pkt->tcpheader->dest;
//         newpacket.tcpheader->dest = pkt->tcpheader->source;
//         newpacket.tcpheader->seq = pkt->tcpheader->ack_seq;
//         newpacket.tcpheader->ack_seq = htons(pktlen + ntohs(pkt->tcpheader->seq));
//         compute_tcp_checksum(newpacket.ipheader, (unsigned short *)newpacket.tcpheader);
// 
//         bytes =
//             sendto(global.af_socket, newpacket.ethernet_frame, (ETH_HDRLEN + IP4_HDRLEN), 0,
//                    (struct sockaddr *)&global.sll, sizeof (global.sll));
//         if (bytes > 0) {
//                 newpacket.len = bytes;
//                 //trace_dump("\n>> GRACK",&newpacket);
//         } else
//                 die(0, "Error sending GRACK");
// 
//         free(newpacket.ethernet_frame);
}
int redirect_ok (char *host) {
  struct list_head *lh;
  struct HDB *entry;
  list_for_each (lh, &(HL.L)) {

    entry = list_entry (lh, struct HDB, L);

    if (entry != NULL) {
      if (strncmp (host, entry->host, strlen (host)) == 0)
        return entry->state;
    }
  }
  return REDIRECT_NEW;
}

void check_redirect (char *host) {
  //fwiw, I copy pasted the curlish parts of this from their example file
  CURL *curl;
  CURLcode res;
  char url[HEADER_DEPTH],
   *location;
  unsigned int response_code,
    state = REDIRECT_DENIED;
  struct HDB *entry = malloc (sizeof (struct HDB));
  if (entry == NULL)
    die (1, "Failed to allocate memory while adding a host entry to HDB");

  snprintf (url, HEADER_DEPTH, "https://%s:%i", host, global.https_port);

  curl = curl_easy_init ();
  if (curl) {
    curl_easy_setopt (curl, CURLOPT_URL, url);
//we're not checking certs because we don't care if it's a valid host, we're just checking if HTTPS is available
// and the server isn't giving us another 301 ,it is up to the user,once redirected to validate certs

    curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
    res = curl_easy_perform (curl);
    if (res == CURLE_OK) {
      res = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
      debug (6, "Response code %i for url %s and host %s\n", response_code, url, host);
      if (res == CURLE_OK) {
        if (response_code == 301) {
          res = curl_easy_getinfo (curl, CURLINFO_REDIRECT_URL, &location);
          if ((res == CURLE_OK) && location && strlen (location) > 7) {
            if (strncasecmp ("http://", location, 7) == 0) {
              state = REDIRECT_DENIED;  //the host is listening on https but redirecting us back to an http url 
              debug (6, "301 redirect for the https url %s returning a http URL %s,marking host as REDIRECT_DENIED\n",
                     url, location);
            } else {
              state = REDIRECT_FOUND;
            }
          }
        } else {
          //host is listening on global.https_port,has TLS/SSL and a response code that isn't 
          //a 301 redirect to another http listening port.
          state = REDIRECT_FOUND;
        }
      } else {
        state = REDIRECT_DENIED;        //unable to get a response code over HTTPS
      }
    } else {
      state = REDIRECT_DENIED;  //unable to curl the https url
    }

  }
  curl_easy_cleanup (curl);
  strncpy (entry->host, host, LINE_LEN);
  entry->state = state;
  list_add (&(entry->L), &(HL.L));


}
