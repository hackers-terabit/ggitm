

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
  
  while(global.run){
    
  }
}


