
#include "ggitm.h"

void http_dump(struct PKT *httppacket){
  int i=0;
    printf("\n--------------------------------------------\n");

  for(i;i<httppacket->datalen;i++){
   printf("%c",httppacket->data[i]); 
  }
      printf("\n--------------------------------------------\n");

}
