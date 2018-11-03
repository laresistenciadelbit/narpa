#include "header.h"

void winarp_sk(int argc, char *argVSK[], int  interfaz)
{
	::optind=0;

  // * getopt * /
  extern char  *optarg;
  optarg=NULL;
  register int opt;
      
  // * WinPcap * /
  LPADAPTER lpAdapter = 0;
  LPPACKET  lpPacket;
  
  // * ARP Packet * /
  struct arp_packet arp_pkt;

  // * Ethernet & ARP packet * /  
  unsigned char	arpsender[ARP_ETH_ADD_SPACE];
  unsigned char	arptarget[ARP_ETH_ADD_SPACE];
  unsigned char	ethersource[ETH_ADD_LEN];
  unsigned char	etherdest[ETH_ADD_LEN];
  unsigned char	ipsource[ARP_IP_ADD_SPACE];
  unsigned char	ipdest[ARP_IP_ADD_SPACE];
  int           opcode;
  
  // * Flags * /
  int flag_mode = 0;
  int flag_delay = 0;
int flag_count = 1;//  int flag_count = 0;
  int flag_dst_ethaddr = 0;
  int flag_src_ethaddr = 0;
  int flag_send_macaddr = 0;
  int flag_send_ipaddr = 0;
  int flag_tar_macaddr = 0;
  int flag_tar_ipaddr = 0;
  int adapter_open = 0;

  // * Others * /
  unsigned int tmpaddr[6];  
  int          delay = TIEMPO_PKT;
  int          count = 1;//int          count = -1;
  int          packetcount = 0;
  int          i;    


  // * Get options * /
  //argc=2; argVSK[1]="-a";

  while((opt = getopt(argc, argVSK, "aig:hm:D:S:d:T:s:F:t:c:")) != EOF) {
	switch(opt) {

		case 'a' :
		case 'e' :   	
		case 'i' :	      	
		case 'g' :	    	
		case 'h' :
		usage();
		exit(EXIT_SUCCESS);      

      // * Number of packets to send * /
      case 'c' :
		if ((count = atoi(optarg)) <= 0) {
			usage();
			exit(EXIT_FAILURE);
		}

		flag_count = 1;
        break;

      // * Delay between packets * /
      case 't' :
		delay = atoi(optarg);
		flag_delay = 1;
        break;

      // * ARP mode (request or reply) * /
      case 'm' :
        if (atoi(optarg) == 1) {
          opcode = ARP_OP_REQUEST;
        } 
        else {
          if (atoi(optarg) == 2) {
            opcode = ARP_OP_REPLY;
          }
          else {
            usage();
			exit(EXIT_FAILURE);
          }
        } ;

		flag_mode = 1;
        break;
      
      // * Ethernet destination address * /
      case 'D' :
        if (strlen(optarg) != 17) {
          usage();
			exit(EXIT_FAILURE);
        }
        
        sscanf(optarg, "%02X-%02X-%02X-%02X-%02X-%02X", &tmpaddr[0], &tmpaddr[1], &tmpaddr[2], &tmpaddr[3], &tmpaddr[4], &tmpaddr[5]);
	       
        for (i = 0; i < 6; i++) {
          etherdest[i] = (unsigned char)tmpaddr[i]; 
        }

        flag_dst_ethaddr = 1;
        memset(tmpaddr, 0, sizeof(tmpaddr));
        break;
        
      // * Ethernet source address * /
      case 'S' :
        if (strlen(optarg) != 17) {
          usage();
			exit(EXIT_FAILURE);
        }
      
        sscanf(optarg, "%02X-%02X-%02X-%02X-%02X-%02X", 
	       &tmpaddr[0], &tmpaddr[1], &tmpaddr[2], 
	       &tmpaddr[3], &tmpaddr[4], &tmpaddr[5]);
	       
        for (i = 0; i < 6; i++) {
          ethersource[i] = (unsigned char)tmpaddr[i]; 
        }

        flag_src_ethaddr = 1;
        memset(tmpaddr, 0, sizeof(tmpaddr));
        break;

      // * Target IP address * /
      case 'd' :
        if ((strlen(optarg) < 7) || (strlen(optarg) > 15)) {
          usage();
			exit(EXIT_FAILURE);
        }
            
        sscanf(optarg, "%d.%d.%d.%d", 
	       &tmpaddr[0], &tmpaddr[1], &tmpaddr[2], 
	       &tmpaddr[3]);
	       
        for (i = 0; i < 4; i++) {
          ipdest[i] = (unsigned char)tmpaddr[i]; 
        }
        
		flag_tar_ipaddr = 1;
        memset(tmpaddr, 0, sizeof(tmpaddr));
        break;
      
      // * Target MAC address * /
      case 'T' :
        if (strlen(optarg) != 17) {
          usage();
			exit(EXIT_FAILURE);
        }      
        
        sscanf(optarg, "%02X-%02X-%02X-%02X-%02X-%02X", 
	       &tmpaddr[0], &tmpaddr[1], &tmpaddr[2], 
	       &tmpaddr[3], &tmpaddr[4], &tmpaddr[5]);
	       
        for (i = 0; i < 6; i++) {
          arptarget[i] = (unsigned char)tmpaddr[i]; 
        }
        
		flag_tar_macaddr = 1;
        memset(tmpaddr, 0, sizeof(tmpaddr));
        break;

      // * Sender IP address * /
      case 's' :		
        if ((strlen(optarg) < 7) || (strlen(optarg) > 15)) {
          usage();
			exit(EXIT_FAILURE);
        }

        sscanf(optarg, "%d.%d.%d.%d", 
	       &tmpaddr[0], &tmpaddr[1], &tmpaddr[2], &tmpaddr[3]);
	       
        for (i = 0; i < 4; i++) {
          ipsource[i] = (unsigned char)tmpaddr[i]; 
        }
        
		flag_send_ipaddr = 1;
        memset(tmpaddr, 0, sizeof(tmpaddr));		  
        break;

      // * Sender MAC address * /
      case 'F' :
        if (strlen(optarg) != 17) {
          usage();
			exit(EXIT_FAILURE);
        }      
      
        sscanf(optarg, "%02X-%02X-%02X-%02X-%02X-%02X", 
	       &tmpaddr[0], &tmpaddr[1], &tmpaddr[2], 
	       &tmpaddr[3], &tmpaddr[4], &tmpaddr[5]);		  
	       
        for (i=0; i<6; i++) {
          arpsender[i] = (unsigned char)tmpaddr[i]; 
        }
        
		flag_send_macaddr = 1;
        memset(tmpaddr, 0, sizeof(tmpaddr));        
        break;			
    }
  }
  
  // * Check minimal options * /
  if((flag_mode && flag_send_ipaddr && flag_tar_ipaddr ) != 1) {
	  
    usage();
	exit(EXIT_FAILURE);
  }

  // * Check ethernet source address * /
  if(flag_src_ethaddr != 1) {  
    if(open_adapter(&lpAdapter,interfaz) == EXIT_FAILURE) {
		exit(EXIT_FAILURE);
	}

	// * if no address is specified the current adapter address is used * /
    get_ether_addr(lpAdapter, ethersource);   
    flag_src_ethaddr = 1;
	adapter_open = 1;
  }

 // * Check ethernet destination address * /
  if((flag_dst_ethaddr != 1)&&(flag_tar_ipaddr == 1)) {  
	if(adapter_open != 1) {
      if(open_adapter(&lpAdapter,interfaz) == EXIT_FAILURE) {
		  exit(EXIT_FAILURE);
	  }

      adapter_open = 1;
	}

	// * if no address is specified the MAC address of ARP Target is used * /
    if(get_remote_mac(lpAdapter, ipdest, etherdest, 0) == EXIT_FAILURE) {
		exit(EXIT_FAILURE);	
	}

    flag_dst_ethaddr = 1;	
  }


  // * Check arp sender MAC address * /
  if(flag_send_macaddr != 1) {  
	if(adapter_open != 1) {
      if(open_adapter(&lpAdapter,interfaz) == EXIT_FAILURE) {
		  exit(EXIT_FAILURE);
	  }

      adapter_open = 1;
	}

	// * if no address is specified the current adapter address is used * /
    get_ether_addr(lpAdapter, arpsender);   
    flag_send_macaddr = 1;	
  }

  // * Check arp target MAC address * /
  if((flag_tar_macaddr != 1)&&(flag_tar_ipaddr == 1)) {  
	if(adapter_open != 1) {
      if(open_adapter(&lpAdapter,interfaz) == EXIT_FAILURE) {
		  exit(EXIT_FAILURE);
	  }

      adapter_open = 1;
	}

	// * if no address is specified the MAC address of ARP Target is used * /
    if(get_remote_mac(lpAdapter, ipdest, arptarget, 0) == EXIT_FAILURE) {
		exit(EXIT_FAILURE);
	}

    flag_tar_macaddr = 1;	
  }  

  // * Check options and set default fields * /
  if ((flag_mode && flag_dst_ethaddr && flag_src_ethaddr && 
       flag_send_macaddr && flag_send_ipaddr && flag_tar_macaddr && 
       flag_tar_ipaddr) != 1) {
    usage();
	exit(EXIT_FAILURE);
  }
    
  // * Open selected adapter * / 
  if(adapter_open != 1) {
    open_adapter(&lpAdapter,interfaz);  
  }

  // * Allocate PACKET structure * /
  if((lpPacket = PacketAllocatePacket()) == NULL) {
    fprintf(stderr, "\nError : failed to allocate the LPPACKET structure");
    PacketCloseAdapter(lpAdapter);
	exit(EXIT_FAILURE);
  }    

  // * Init packet structure * /
  memset(&arp_pkt, 0, sizeof(struct arp_packet));         

  // * Build custom ARP packet * /
  arp_build(&arp_pkt, etherdest, ethersource, opcode, arpsender, ipsource, arptarget, ipdest);     
 
  // * Init packet * /
  PacketInitPacket(lpPacket, &arp_pkt, sizeof(arp_pkt));
		
  // * Set number of packets to send * /
  if(PacketSetNumWrites(lpAdapter, 1) == FALSE) {
    fprintf(stderr, "\nWarning : unable to send more than one packet in a single write\n");
  }

  // * Print start informations * /
  //if(flag_mode==1)	  print_start(etherdest, ethersource, opcode, arpsender, ipsource, arptarget, ipdest);

  while(1){
    if(PacketSendPacket(lpAdapter, lpPacket, TRUE) == FALSE){
      fprintf(stderr, "\nError : unable to send the packets\n");	        
      PacketCloseAdapter(lpAdapter);
      PacketFreePacket(lpPacket);
		exit(EXIT_FAILURE);
	}
	packetcount++;

	if((packetcount % 46) == 0) {
      printf("\n  ");
	}

	Sleep(delay);

	if (count > 0) {
	  count--;
	  if( !((count != 0) && (count != -1)) ) {	
        PacketFreePacket(lpPacket);
		close_adapter(lpAdapter);
		return;      
	  }
	}	

	if(_kbhit()) {
	  PacketFreePacket(lpPacket);
	  close_adapter(lpAdapter);
        
		return;
	}
  }
  
}