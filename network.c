

#include "network.h"

void
get_interface (char *if_name, struct ifreq *ifr, int d) {

  size_t if_name_len = strlen (if_name);

  if (if_name_len < sizeof (ifr->ifr_name)) {
    memcpy (ifr->ifr_name, if_name, if_name_len);
    ifr->ifr_name[if_name_len] = 0;
  }
  else {
    die (0, "interface name is too long");
  }
  int fd = socket (AF_INET, SOCK_DGRAM, 0);

  if (fd == -1) {
    die (0, if_name);
  }
  else {
    switch (d) {

	    case IFINDEX:
	      if (ioctl (fd, SIOCGIFINDEX, ifr) == -1) {
		die (0, "IFINDEX");
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


int
ifup (char *if_name) {
  struct ifreq ifr;
  struct sockaddr_ll sll;
  size_t if_name_len = strlen (if_name);

  if (if_name_len < sizeof (ifr.ifr_name)) {
    memcpy (ifr.ifr_name, if_name, if_name_len);
    ifr.ifr_name[if_name_len] = 0;
  }
  else {
    die (0, "interface name is too long");
  }
  int fd = socket (AF_UNIX, SOCK_DGRAM, 0);

  if (fd == -1) {
    die (0, if_name);
  }
  if (ioctl (fd, SIOCGIFFLAGS, &ifr) == -1) {
    die (0, if_name);
  }
  else {
    int flag = ifr.ifr_flags;

    if (flag & IFF_UP) {
      printf ("%s is UP\r\n", if_name);
    }
    else if (!(flag & IFF_UP)) {
      printf ("%s is DOWN. bringing interface UP\r\n", if_name);
      ifr.ifr_flags |= IFF_UP;

      if (ioctl (fd, SIOCSIFFLAGS, &ifr) == -1) {
	die (0, "Interface turn up");
      }
      else {
	printf ("Successfully brought %s back online\r\n", if_name);
      }
    }
  }

  global.af_socket=init_af_packet(if_name,&sll);

 if(global.af_socket < 1) 
    die(1,"Error initiating af_packet socket!.");
 else global.run=1;
  return 0;
}



int ifdown(char *interface){
  
  
}

int
init_af_packet (char *ifname, struct sockaddr_ll *sll) {
  int index, fd = -1;
  struct ifreq ifr;

  get_interface (ifname, &ifr, IFINDEX);
  if (ifr.ifr_ifindex < 1) {
    die (1, "ERROR - Unable to get interfce index for %s\r\n", ifname);
  }
  else {
    fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if(fd<1)die(1,"ERROR creating AF_PACKET socket for %s\r\n",ifname);
    
    bind(fd,(struct sockaddr *) sll,sizeof(struct sockaddr_ll));
    
  }

  return fd;
}


void capture_loop (struct global_settings global){
        struct ifreq ifr;

 get_interface (global.interface_in, &ifr, IFMTU); 
 //drop_privs();

  struct PKT *packetv4=malloc(sizeof(struct PKT));
  struct pollfd pfd;
  uint8_t ip_protocol;
  uint16_t l4port;
  packetv4->mtu=ifr.ifr_mtu;
  packetv4->ethernet_frame=malloc(packetv4->mtu);
  packetv4->ipheader=(struct iphdr *) (packetv4->ethernet_frame+ETH_HDRLEN);
  
    pfd.fd = global.af_socket;
    pfd.events = POLLIN;

  while(global.run){
    
            poll ( &pfd, 1, -1 );
	   
	    if ( pfd.revents & POLLIN )
		packetv4->len = read ( pfd.fd, packetv4->ethernet_frame, packetv4->mtu );	

	    if ( packetv4->len < 1) {
		die ( 0, "Error in receiving frame\n" );
	
	    }else{
	      ip_protocol=packetv4->ipheader->protocol;
	      if(ip_protocol==0x11){ //UDP
		packetv4->udpheader=(struct udphdr *) (packetv4->ethernet_frame+ETHIP4);
		packetv4->data=(uint8_t *) (packetv4->ethernet_frame+(ETHIP4+sizeof(struct udphdr))); //gonna need to be smarter about header sizes..
                packetv4->datalen=packetv4->len - (ETHIP4+sizeof(struct udphdr)); 
		l4port=ntohs(packetv4->udpheader->dest);
		
		if(l4port==53){
		  dns_dump(packetv4);
		}
	      }else if(ip_protocol==0x06){ //TCP
		packetv4->tcpheader=(struct tcphdr *) (packetv4->ethernet_frame+ETHIP4);
       		packetv4->data=(uint8_t *) (packetv4->ethernet_frame+(ETHIP4+(4*packetv4->tcpheader->doff)));
                packetv4->datalen=packetv4->len - (ETHIP4+(4*packetv4->tcpheader->doff));

		l4port=ntohs(packetv4->tcpheader->dest);
                  if(l4port==global.http_port){
		   http_packet(packetv4); 
		    
		  }else{
		 //  printf("TCP port %i\n",l4port); 
		  }
	      }else{
		//printf (" NOT TCP/UDP got %x\n",ip_protocol		);
	      }
	    }
	    
  }
}

void trace_dump (char *msg,struct PKT * packet) {
  int i = 0;

  printf
    ("\r\n+----------------------------{%s}len:%i-----------------------------------------+\r\n",
      msg, packet->len);

  for (i = 0; i < ETH_HDRLEN; i++) {
    printf ("\033[1;32m%02x", packet->ethernet_frame[i]);
  }
//	  exit(0);
  printf ("\r\n\0******************************************************************************\r\n");
  for (i; i < ETHIP4; i++) {
    printf ("\033[1;33m%02x", packet->ethernet_frame[i]);
  }
  printf ("\r\n******************************************************************************\r\n");
  for (i; i < packet->len + (ETHIP4); i++) {
    printf ("\033[1;34m%02x", packet->ethernet_frame[i]);
  }
  printf("\n");
}

