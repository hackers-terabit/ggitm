
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

int ifup (char *if_name, int direction) {
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
               ifr.ifr_flags &= IFF_UP;
	  
               ifr.ifr_flags &= IFF_PROMISC;
               ifr.ifr_flags &= IFF_BROADCAST;
               ifr.ifr_flags &= IFF_ALLMULTI;
	       
               if (ioctl (fd, SIOCSIFFLAGS, &ifr) == -1) {
                    die (0, "Failed Interface turn up");
               } else {
                    printf ("Successfully brought %s back online\r\n", if_name);
               }
          }
     }

     global.run = 1;
     return 0;
}

int ifdown (char *interface) {
     // close (global.af_socket);
}

int init_af_packet (char *ifname, struct sockaddr_ll *sll) {
     int index, fanout_arg;
     static int fanout_id = 1;
     int fd = -1;
     struct ifreq ifr;

     get_interface (ifname, &ifr, IFINDEX);
     if (ifr.ifr_ifindex < 1) {
          die (1, "ERROR - Unable to get interfce index for %s\r\n", ifname);
     } else {
          fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
          if (fd < 1)
               die (1, "ERROR creating AF_PACKET socket for %s\r\n", ifname);

          if(bind (fd, (struct sockaddr *) sll, sizeof (struct sockaddr_ll))!=0)
	    die(1,"Error binding af_packet file descriptor for interface %s\r\n",ifname);
          fanout_arg = (++fanout_id | (PACKET_FANOUT_LB << 16));
          if (setsockopt (fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof (fanout_arg)))
               die (0, "Error setting up AF_PACKET FANOUT\r\n");

     }

     return fd;
}
void start_loops () {
     int i;
     pthread_t *handle, *handle2;
          handle2 = malloc (sizeof (pthread_t));

     for (i = 0;  i < global.cpu_available ; i++) {
          handle = malloc (sizeof (pthread_t));

          if (global.mode == IL) {

               if (pthread_create (handle, 0, copy_loop, (void *) NULL))
                    die (1, "Error creating copy_loop threads");
          }
          if (pthread_create (handle2, 0, capture_loop, (void *) NULL))
               die (1, "Error creating copy_loop threads");
          

     }
                      pthread_join (*handle2, NULL);


}
void write_out (int fd, int len, struct traffic_context tcx) {
     int bytes;
     if (global.mode == IL) {
      bytes = sendto (fd, tcx.pkt->ethernet_frame,
                    len, 0, (struct sockaddr *) &tcx.sll_out, sizeof (struct sockaddr_ll));
     //    bytes = write (fd, tcx.pkt->ethernet_frame, len);
          if (bytes < tcx.pkt->len) {
               die (0, "Error copying packet to egress interface, original size %i sendto transimtted %i\r\n",
                    tcx.pkt->len, bytes);
          }
     }
     //trace_dump("write_out()",tcx.pkt);
}
void sll_setup_out (char *interface, struct traffic_context *tcx) {
     if (interface == NULL || tcx == NULL || strlen (interface) < 1)
          die(1,"Error in sll_setup_out");
     struct ifreq ifr;

     get_interface (interface, &ifr, IFINDEX);
     tcx->sll_out.sll_ifindex = ifr.ifr_ifindex;;
     tcx->sll_out.sll_halen = 6;
     tcx->sll_out.sll_protocol = htons (ETH_P_ALL);
     tcx->sll_out.sll_family = AF_PACKET;
     if(global.mode==IL){
     tcx->sll_out.sll_pkttype |= PACKET_HOST;
     tcx->sll_out.sll_pkttype |= PACKET_BROADCAST;
     tcx->sll_out.sll_pkttype |= PACKET_MULTICAST;
     tcx->sll_out.sll_pkttype |= PACKET_OTHERHOST;
     tcx->sll_out.sll_pkttype |= PACKET_OUTGOING;
     }
}
void sll_setup_in (char *interface, struct traffic_context *tcx) {
     if (interface == NULL || tcx == NULL || strlen (interface) < 1)
          die(1,"Error in sll_setup_in");
     struct ifreq ifr;

     get_interface (interface, &ifr, IFINDEX);
     tcx->sll_in.sll_ifindex = ifr.ifr_ifindex;;
     tcx->sll_in.sll_halen = 6;
     tcx->sll_in.sll_protocol = htons (ETH_P_ALL);
     tcx->sll_in.sll_family = AF_PACKET;
     if(global.mode==IL){
     tcx->sll_in.sll_pkttype |= PACKET_HOST;
     tcx->sll_in.sll_pkttype |= PACKET_BROADCAST;
     tcx->sll_in.sll_pkttype |= PACKET_MULTICAST;
     tcx->sll_in.sll_pkttype |= PACKET_OTHERHOST;
     tcx->sll_in.sll_pkttype |= PACKET_OUTGOING;
     }
}
void init_traffic_context (struct traffic_context *tcx) {
     struct ifreq ifr;
     int tcpoffset = 0, i = 0;

     tcx->pkt =
          malloc_or_die ("Capture loop exiting due to failure to allocate %i bytes of memory", sizeof (struct PKT),
                         sizeof (struct PKT));

     if (global.mode == IL) {
          sll_setup_out (global.interface_out, tcx);
     }

    
     sll_setup_in (global.interface_in, tcx);
     debug (4, "%s is the interface %i is the index\r\n", global.interface_in, tcx->sll_in.sll_ifindex);

     tcx->fd_in = init_af_packet (global.interface_in, &tcx->sll_in);
     if (tcx->fd_in < 1)
          die (1, "Error initiating af_packet socket!.");
     if (global.mode == IL) {
          tcx->fd_out = init_af_packet (global.interface_out, &tcx->sll_out);

          if (tcx->fd_out < 1)
               die (1, "Error initiating af_packet socket!.");
     }

     get_interface (global.interface_in, &ifr, IFMTU);
     tcx->pkt->mtu = ifr.ifr_mtu;
     tcx->pkt->ethernet_frame = malloc (tcx->pkt->mtu);
     tcx->pkt->ipheader = (struct iphdr *) (tcx->pkt->ethernet_frame + ETH_HDRLEN);
     tcx->pkt->tcpheader = (struct tcphdr *) (tcx->pkt->ethernet_frame + ETHIP4);
     tcx->pkt->udpheader = (struct udphdr *) (tcx->pkt->ethernet_frame + ETHIP4);

}
void *capture_loop (void *arg) {
     struct traffic_context tcx;
     
     struct pollfd pfd;
     uint16_t l4port, tcpoffset;
  init_traffic_context (&tcx);
     pfd.fd = tcx.fd_in;
     pfd.events = POLLIN;
     drop_privs ();
     debug (3, "Initialization complete,packet processing is starting now.\r\n");
     
     while (global.run) {
          memset (tcx.pkt->ethernet_frame, 0, tcx.pkt->mtu);
          poll (&pfd, 1, -1);
          if (pfd.revents & POLLIN)
               tcx.pkt->len = read (tcx.fd_in, tcx.pkt->ethernet_frame, tcx.pkt->mtu);
          if (tcx.pkt->len)
               write_out (tcx.fd_out, tcx.pkt->len, tcx);

          if (tcx.pkt->len < ETHIP4 + sizeof (struct udphdr)) { //discard invalid packets
               debug (6, "Error in receiving frame,packet too short - size %i fd:%i\n", tcx.pkt->len, pfd.fd);
               write_out (tcx.fd_out, tcx.pkt->len, tcx);
               continue;
          } else {
               if (tcx.pkt->ipheader->protocol == 0x11) {       //UDP
                    tcx.pkt->data = (uint8_t *) (tcx.pkt->ethernet_frame + (ETHIP4 + sizeof (struct udphdr)));  //gonna need to be smarter about header sizes..
                    tcx.pkt->datalen = tcx.pkt->len - (ETHIP4 + sizeof (struct udphdr));
                    l4port = ntohs (tcx.pkt->udpheader->dest);
               } else if (tcx.pkt->ipheader->protocol == 0x06) {        //TCP
                    if (tcx.pkt->len < ETHIP4 + sizeof (struct tcphdr)) {       //discard invalid tcp packets
                         debug (6, "Error in receiving frame,packet too short for TCP - size %i \n", tcx.pkt->len);
                         write_out (tcx.fd_out, tcx.pkt->len, tcx);
                         continue;
                    }
                    tcpoffset = (4 * tcx.pkt->tcpheader->doff);
                    tcpoffset = (tcpoffset > tcx.pkt->len || (tcpoffset + ETHIP4) > tcx.pkt->len) ? tcx.pkt->len - ETHIP4 : tcpoffset;  //sanity?
                    tcx.pkt->data = (uint8_t *) (tcx.pkt->ethernet_frame + (ETHIP4 + tcpoffset));
                    tcx.pkt->datalen = tcx.pkt->len - (ETHIP4 + sizeof (struct tcphdr));

                    l4port = ntohs (tcx.pkt->tcpheader->dest);
                    if (l4port == global.http_port) {

                         if (http_packet (tcx) && global.mode == IL) {
                            //  write_out (tcx.fd_out, tcx.pkt->len, tcx);
                         }      //else we don't care just ignore it
                    } else {
                       //  write_out (tcx.fd_out, tcx.pkt->len, tcx);
                    }
               }
               //write_out (tcx.fd_out, tcx.pkt->len, tcx);
          }
     }
     free (tcx.pkt);
     free (tcx.pkt->ethernet_frame);
}
void *copy_loop (void *arg) {
     struct ifreq ifr;
     int bytes, bytes2, mtu;
     struct pollfd pfd;

     struct traffic_context tcx;
     init_traffic_context (&tcx);
     get_interface (global.interface_in, &ifr, IFMTU);
     mtu = ifr.ifr_mtu < 64 ? 1500 : ifr.ifr_mtu;

     pfd.fd = tcx.fd_out;
     pfd.events = POLLIN;

     while (global.run) {
          memset (tcx.pkt->ethernet_frame, 0, tcx.pkt->mtu);

          poll (&pfd, 1, -1);

          if (pfd.revents & POLLIN)
               tcx.pkt->len = read (tcx.fd_out, tcx.pkt->ethernet_frame, mtu);

          if (tcx.pkt->len < ETH_HDRLEN)
               die (0, "Error reading packets in copy_loop\r\n");
          else {
               write_out (tcx.fd_in, tcx.pkt->len, tcx);
//       bytes2 = sendto (tcx.fd_in, tcx.pkt->ethernet_frame, bytes, 0, (struct sockaddr *) &tcx.sll_in, sizeof (struct sockaddr_ll));
//       if (bytes2 != bytes)
//         die (0, "Packet retransmission error in copy_loop in:%i out:%i \r\n", bytes, bytes2);
               trace_dump ("copy_loop()", tcx.pkt);

          }
     }

}
void trace_dump (char *msg, struct PKT *packet) {
     if (global.debug < 7 || packet == NULL || packet->ethernet_frame == NULL)
          return;
     int i = 0,chk= packet==NULL? 0: packet->ipheader->check;
     if (packet->len > 1499)
          return;
     printf
          ("\r\n+----------------------------{%s}len:%i<checksum:%02x-----------------------------------------+\r\n", msg,
           packet->len,ntohs(chk));

     for (i = 0; i < ETH_HDRLEN; i++) {
          // if(isprint(packet->ethernet_frame[i]))
          printf ("\033[1;32m%x.", packet->ethernet_frame[i]);
     }
//        exit(0);
     printf ("\r\n\0******************************************************************************\r\n");
     for (i; i < packet->len  && i < ETHIP4 ; i++) {
          //    if(isprint(packet->ethernet_frame[i]))
          printf ("\033[1;33m%02x.", packet->ethernet_frame[i]);
     }
     printf ("\r\n******************************************************************************\r\n");
     for (i; i < packet->len  && i < sizeof (struct tcphdr) + (ETHIP4); i++) {
          //  if(isprint(packet->ethernet_frame[i]))
          printf ("\033[1;34m%02x.", packet->ethernet_frame[i]);
     }
     printf ("\r\n******************************************************************************\r\n");
     for (i; i < packet->len  && i < packet->len ; i++) {
          //  if(isprint(packet->ethernet_frame[i]))
          printf ("\033[1;34m%x.", packet->ethernet_frame[i]);
     }
     printf ("\n");
}
