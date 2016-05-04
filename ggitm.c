
#include "ggitm.h"
#define _GNU_SOURCE
void http_dump(struct PKT *httppacket){
  int i=0;
    printf("\n--------------------------------------------\n");

  for(i;i<httppacket->datalen;i++){
   printf("%c",httppacket->data[i]); 
  }
      printf("\n--------------------------------------------\n");

}


int get_http_host(uint8_t *data,char *buf,int bufsz){
 char *tmp,*tmp2,c;
 int n=0,i=0;
 char *chardata= (char *) data;
 char *s=strcasestr(chardata,"host:");
   
   if(s==NULL || (strlen(s) < 6))
      return 0;
   else{
     s=&s[6];
     for (i; i<bufsz;i++){
       c=s[i];
       if (c == ':' || c == '\r' || c == '\n' || c== '\0' || (!isprint(c)))
	 break;
       else
	 buf[i]=c;
     }
      if (i<3) return 0;
      
      return 1;
   }
  return 0;
}

void http_packet(struct PKT *httppacket){
      int hlen= httppacket->datalen < 256 ? httppacket->datalen : 255;

   char buf[hlen];
   memset(buf,0,hlen);
  if (get_http_host(httppacket->data,buf,hlen)){
    debug(4,"TCP seq: %x<>%x - HTTP host header found: --%s--\r\n",ntohl(httppacket->tcpheader->seq),ntohl(httppacket->tcpheader->ack_seq),buf);
     
     if(redirect_ok(buf)){
      grack(httppacket);
      send_301(httppacket);
      kill_session(httppacket);
     }
    
  }
}

void send_301(struct PKT *httppacket){
  
}
void kill_session(struct PKT*pkt){
  
}
void grack(struct PKT *pkt){
  struct PKT newpacket;
  int pktlen;
  pktlen=ntohs(pkt->ipheader->tot_len)- (IP4_HDRLEN+sizeof(struct tcphdr));//this will break if tcp/ip header length is non-default,needs to be fixed //TODO
  newpacket.ethernet_frame=malloc(pkt->mtu);
  memset(newpacket.ethernet_frame,0,pkt->mtu);
  
  newpacket.ipheader=(struct iphdr *) (newpacket.ethernet_frame+ETH_HDRLEN);
  newpacket.tcpheader=(struct tcphdr *) (newpacket.ethernet_frame+ETHIP4);

  memcpy(newpacket.ethernet_frame,&pkt->ethernet_frame[6],6); //old src mac -> new dst mac
  memcpy(&newpacket.ethernet_frame[6],pkt->ethernet_frame,6); //old dst mac -> new src mac
  
  
  memcpy(newpacket.ipheader,pkt->ipheader,IP4_HDRLEN);
  newpacket.ipheader->daddr=pkt->ipheader->saddr;
  newpacket.ipheader->saddr=pkt->ipheader->daddr;
  newpacket.ipheader->tot_len=htonl(IP4_HDRLEN+sizeof(struct tcphdr));
  newpacket.ipheader->check=csum((unsigned short*)newpacket.ipheader,IP4_HDRLEN);
  
  newpacket.tcpheader->window=pkt->tcpheader->window;
  newpacket.tcpheader->ack=1;
  newpacket.tcpheader->source=pkt->tcpheader->dest;
  newpacket.tcpheader->dest=pkt->tcpheader->source;
  newpacket.tcpheader->seq=pkt->tcpheader->ack_seq;
  newpacket.tcpheader->ack_seq=htons(pktlen+ntohs(pkt->tcpheader->seq));
  
  
}
int  redirect_ok(char *host){
 
  return 1;
}