
#include "network.h"

void get_interface (char *if_name, struct ifreq *ifr, int d) {

  size_t if_name_len = strlen (if_name);

  if (if_name_len < sizeof (ifr->ifr_name)) {
    memcpy (ifr->ifr_name, if_name, if_name_len);
    ifr->ifr_name[if_name_len] = 0;
  } else {
    die (0, "interface name is too long");
  }
  int fd = socket (AF_INET, SOCK_DGRAM, 0);

  if (fd == -1) {
    die (0, if_name);
  } else {
    switch (d) {

    case IFINDEX:
      if (ioctl (fd, SIOCGIFINDEX, ifr) == -1) {
        die (1, "IFINDEX:  ");
      }
      break;
    case IFMAC:
      if (ioctl (fd, SIOCGIFHWADDR, ifr) == -1) {
        die (0, "IFMAC");
      }
      break;
    case IFMTU:
      if (ioctl (fd, SIOCGIFMTU, ifr) == -1) {
        die (0, "IFMTU");
      }
      break;
    case IFADDR:
      if (ioctl (fd, SIOCGIFADDR, ifr) == -1) {
      }
      break;
    default:
      break;
    }
    close (fd);
  }
}

int ifup (char *if_name,int direction) {
  struct ifreq ifr;
  size_t if_name_len = strlen (if_name);

  if (if_name_len < sizeof (ifr.ifr_name)) {
    memcpy (ifr.ifr_name, if_name, if_name_len);
    ifr.ifr_name[if_name_len] = 0;
  } else {
    die (0, "interface name is too long");
  }
  int fd = socket (AF_UNIX, SOCK_DGRAM, 0);

  if (fd == -1) {
    die (0, if_name);
  }
  if (ioctl (fd, SIOCGIFFLAGS, &ifr) == -1) {
    die (0, if_name);
  } else {
    int flag = ifr.ifr_flags;

    if (flag & IFF_UP) {
      printf ("%s is UP\r\n", if_name);
    } else if (!(flag & IFF_UP)) {
      printf ("%s is DOWN. bringing interface UP\r\n", if_name);
      ifr.ifr_flags |= IFF_UP;

      if (ioctl (fd, SIOCSIFFLAGS, &ifr) == -1) {
        die (0, "Interface turn up");
      } else {
        printf ("Successfully brought %s back online\r\n", if_name);
      }
    }
  }


  
    global.run = 1;
  return 0;
}

int ifdown (char *interface) {
  close (global.af_socket);
}

int init_af_packet (char *ifname, struct sockaddr_ll *sll) {
  int index,fanout_arg;
  static int fanout_id=1;
    int fd = -1;
  struct ifreq ifr;

  get_interface (ifname, &ifr, IFINDEX);
  if (ifr.ifr_ifindex < 1) {
    die (1, "ERROR - Unable to get interfce index for %s\r\n", ifname);
  } else {
    fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if (fd < 1)
      die (1, "ERROR creating AF_PACKET socket for %s\r\n", ifname);

    bind (fd, (struct sockaddr *) sll, sizeof (struct sockaddr_ll));
 fanout_arg = (++fanout_id | (PACKET_FANOUT_LB<< 16)); 
        if( setsockopt(fd, SOL_PACKET, PACKET_FANOUT,
                         &fanout_arg, sizeof(fanout_arg)))
	  die(0,"Error setting up AF_PACKET FANOUT\r\n");
       


  }

  return fd;
}
void start_loops(){
  int i;
  pthread_t *handle,*handle2;
 for(i=0;i<global.cpu_available;i++){
   handle = malloc (sizeof (pthread_t));
   handle2 = malloc (sizeof (pthread_t));

 if(global.mode==0){
   
  if( pthread_create (handle, 0, copy_loop, (void *) NULL))
    die(1,"Error creating copy_loop threads");
 }
  if( pthread_create (handle2, 0, capture_loop, (void *) NULL))
    die(1,"Error creating copy_loop threads");
   else    pthread_join (*handle2, NULL);

 }

   
}
void *capture_loop (void *arg) {
  struct ifreq ifr;

  

  struct PKT *packetv4 = malloc (sizeof (struct PKT));
  if (packetv4 == NULL) {
    die (0, "Capture loop exiting due to failure to allocate %i bytes of memory", sizeof (struct PKT));
    return;
  }
  struct pollfd pfd;
  uint8_t ip_protocol;
  uint16_t l4port;
  int tcpoffset = 0,bytes=0,i=0,fd_in,fd_out;
  struct sockaddr_ll sll_in,sll_out;
//   if(global.mode==0){
//   get_interface (global.interface_out, &ifr, IFINDEX);
//   sll_out.sll_ifindex = ifr.ifr_ifindex;;
//   sll_out.sll_halen = 6;
//   sll_out.sll_protocol = htons (ETH_P_ALL);
//   sll_out.sll_family = AF_PACKET;
//   }
  get_interface (global.interface_in, &ifr, IFINDEX);
  sll_in.sll_ifindex = ifr.ifr_ifindex;;
  sll_in.sll_halen = 6;
  sll_in.sll_protocol = htons (ETH_P_ALL);
  sll_in.sll_family = AF_PACKET;
   debug(4,"%s is the interface %i is the index\r\n",global.interface_in,ifr.ifr_ifindex);
  fd_in = init_af_packet (global.interface_in, &sll_in);
  if (fd_in < 1)
    die (1, "Error initiating af_packet socket!.");
// if(global.mode==0){
//   fd_out = init_af_packet (global.interface_out, &sll_out);
// 
//   if (fd_out < 1)
//     die (1, "Error initiating af_packet socket!.");
// }

get_interface (global.interface_in, &ifr, IFMTU);
  packetv4->mtu = ifr.ifr_mtu;
  packetv4->ethernet_frame = malloc (packetv4->mtu);
  packetv4->ipheader = (struct iphdr *) (packetv4->ethernet_frame + ETH_HDRLEN);

  pfd.fd = fd_in;
  pfd.events = POLLIN;
  
  drop_privs ();
  debug (3, "Initialization complete,packet processing is starting now.");
  while (global.run) {
    memset (packetv4->ethernet_frame, 0, packetv4->mtu);
    poll (&pfd, 1, -1);

    if (pfd.revents & POLLIN)
      packetv4->len = read (fd_in, packetv4->ethernet_frame, packetv4->mtu);

    if (packetv4->len < ETHIP4 + sizeof (struct udphdr)) {      //discard invalid packets
      debug (6, "Error in receiving frame,packet too short - size %i fd:%i\n", packetv4->len,pfd.fd);
      continue;

    } else {

      ip_protocol = packetv4->ipheader->protocol;
      if (ip_protocol == 0x11) {        //UDP
        packetv4->udpheader = (struct udphdr *) (packetv4->ethernet_frame + ETHIP4);
        packetv4->data = (uint8_t *) (packetv4->ethernet_frame + (ETHIP4 + sizeof (struct udphdr)));    //gonna need to be smarter about header sizes..
        packetv4->datalen = packetv4->len - (ETHIP4 + sizeof (struct udphdr));
        l4port = ntohs (packetv4->udpheader->dest);

        if (l4port == 53) {
          dns_dump (packetv4);
        }
           bytes = sendto (fd_out, packetv4->ethernet_frame,
                    packetv4->len, 0, (struct sockaddr *) &sll_out, sizeof (sll_out));
             if(bytes < packetv4->len){
	       die(0,"Error copying packet to egress interface, original size %i sendto transimtted %i\r\n",packetv4->len,bytes);
	     }

      } else if (ip_protocol == 0x06) { //TCP
        if (packetv4->len < ETHIP4 + sizeof (struct tcphdr)) {  //discard invalid tcp packets
          debug (6, "Error in receiving frame,packet too short for TCP - size %i \n", packetv4->len);
          continue;

        }

        packetv4->tcpheader = (struct tcphdr *) (packetv4->ethernet_frame + ETHIP4);
        tcpoffset = (4 * packetv4->tcpheader->doff);
        tcpoffset = (tcpoffset > packetv4->len || (tcpoffset + ETHIP4) > packetv4->len) ? packetv4->len - ETHIP4 : tcpoffset;   //sanity?
        packetv4->data = (uint8_t *) (packetv4->ethernet_frame + (ETHIP4 + tcpoffset));
        packetv4->datalen = packetv4->len - (ETHIP4 + tcpoffset);

        l4port = ntohs (packetv4->tcpheader->dest);
        if (l4port == global.http_port) {
          //this is to make it easier to read debug outputs for debug levels 5 and above
          debug (5, "\r\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\r\n");
          //if(
	    http_packet (packetv4,pfd.fd,sll_in) ;
// 	    && !(global.mode)){
// 	   //inline mode,packet accepted,let's copy it! 
// 	    
// 	    bytes = sendto (fd_out, packetv4->ethernet_frame,
//                     packetv4->len, 0, (struct sockaddr *) &global.sll_out, sizeof (sll_out));
//              if(bytes < packetv4->len){
// 	       die(0,"Error copying packet to egress interface, original size %i sendto transimtted %i\r\n",packetv4->len,bytes);
// 	     }
	  //}//else we don't care just ignore it

        } else {
        }
      } else {
	   bytes = sendto (fd_out, packetv4->ethernet_frame,
                    packetv4->len, 0, (struct sockaddr *) &global.sll_out, sizeof (sll_out));
             if(bytes < packetv4->len){
	       die(0,"Error copying packet to egress interface, original size %i sendto transimtted %i\r\n",packetv4->len,bytes);
	     }
      }
    }

  }

  free (packetv4);
  free (packetv4->ethernet_frame);
}
void *copy_loop(void *arg){
   struct ifreq ifr;
  int bytes,bytes2,fd_in,fd_out;
    struct pollfd pfd;

  
  get_interface (global.interface_in, &ifr, IFMTU);
  
  uint8_t *ethernet_frame=malloc(ifr.ifr_mtu);
  
 if(ethernet_frame==NULL)
    die(1,"copy_loop malloc() error\r\n");
   struct sockaddr_ll sll_in,sll_out;
  get_interface (global.interface_out, &ifr, IFINDEX);
  sll_out.sll_ifindex = ifr.ifr_ifindex;;
  sll_out.sll_halen = 6;
  sll_out.sll_protocol = htons (ETH_P_ALL);
  sll_out.sll_family = AF_PACKET;
  get_interface (global.interface_in, &ifr, IFINDEX);
  sll_in.sll_ifindex = ifr.ifr_ifindex;;
  sll_in.sll_halen = 6;
  sll_in.sll_protocol = htons (ETH_P_ALL);
  sll_in.sll_family = AF_PACKET;
   
  fd_in = init_af_packet (global.interface_in, &sll_in);
  if (fd_in < 1)
    die (1, "Error initiating af_packet socket!.");

  fd_out = init_af_packet (global.interface_out, &sll_out);

  if (fd_out < 1)
    die (1, "Error initiating af_packet socket!.");
  
pfd.fd = fd_out;
  pfd.events = POLLIN;
  
 while(global.run){
      poll (&pfd, 1, -1);

    if (pfd.revents & POLLIN)
     bytes = read (pfd.fd, ethernet_frame, ifr.ifr_mtu);
     if(bytes<ETH_HDRLEN)
       debug(4,"Error reading packets in copy_loop\r\n");
    else{
      bytes2=sendto(fd_in,ethernet_frame,bytes,0, (struct sockaddr *) &sll_in, sizeof (struct sockaddr_ll));
      if(bytes2!=bytes)
         die(0,"Packet retransmission error in copy_loop in:%i out:%i \r\n",bytes,bytes2);
     
    }
  }
  
}
void trace_dump (char *msg, struct PKT *packet) {
  if (global.debug < 7)
    return;
  int i = 0;

  printf
    ("\r\n+----------------------------{%s}len:%i-----------------------------------------+\r\n", msg, packet->len);

  for (i = 0; i < ETH_HDRLEN; i++) {
    // if(isprint(packet->ethernet_frame[i]))
    printf ("\033[1;32m%c.", packet->ethernet_frame[i]);
  }
//        exit(0);
  printf ("\r\n\0******************************************************************************\r\n");
  for (i; i < ETHIP4; i++) {
    //    if(isprint(packet->ethernet_frame[i]))
    printf ("\033[1;33m%02x.", packet->ethernet_frame[i]);
  }
  printf ("\r\n******************************************************************************\r\n");
  for (i; i < sizeof (struct tcphdr) + (ETHIP4); i++) {
    //  if(isprint(packet->ethernet_frame[i]))
    printf ("\033[1;34m%02x.", packet->ethernet_frame[i]);
  }
  printf ("\r\n******************************************************************************\r\n");
  for (i; i < packet->len; i++) {
    //  if(isprint(packet->ethernet_frame[i]))
    printf ("\033[1;34m%c", packet->ethernet_frame[i]);
  }
  printf ("\n");
}
