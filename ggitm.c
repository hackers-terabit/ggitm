
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
  }
}