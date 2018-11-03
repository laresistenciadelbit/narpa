#include "header.h"

extern char macaux[18];
extern char ipeq[16];
extern bool primera_vez;

void transforma_a_ipU (char* ipini,  unsigned char ipfin[4] );

int arp_build(struct arp_packet *arp_pkt, unsigned char *dst_etheraddr, 
			  unsigned char *src_etheraddr, int ar_op, unsigned char *ar_sha, 
			  unsigned char *ar_sip, unsigned char *ar_tha, unsigned char *ar_tip) 
{  
  // * Set ethernet header * /
  memcpy(&(arp_pkt->eth_dst_addr), dst_etheraddr, ETH_ADD_LEN);      
  memcpy(&(arp_pkt->eth_src_addr), src_etheraddr, ETH_ADD_LEN);
  arp_pkt->eth_type = htons(ETH_TYPE_ARP);  

  // * Set ARP header * /
  arp_pkt->ar_hrd = htons(ARP_HW_ETH);
  arp_pkt->ar_pro = htons(ARP_PRO_IP);
  arp_pkt->ar_hln = ARP_ETH_ADD_SPACE;
  arp_pkt->ar_pln = ARP_IP_ADD_SPACE;
  arp_pkt->ar_op  = htons(ar_op);

  memcpy(&(arp_pkt->ar_sha), ar_sha, ARP_ETH_ADD_SPACE);
  memcpy(&(arp_pkt->ar_spa), ar_sip, ARP_IP_ADD_SPACE);
  memcpy(&(arp_pkt->ar_tha), ar_tha, ARP_ETH_ADD_SPACE);
  memcpy(&(arp_pkt->ar_tpa), ar_tip, ARP_IP_ADD_SPACE);
	
  // * Set ethernet padding * /
  memset(arp_pkt->eth_pad, 32, ETH_PADDING_ARP);

  return(EXIT_SUCCESS);
}


void usage() 
{
	printf("\n\n\t\t** Error interno **");
	/*uso del winarp_sk*/
}


void get_ether_addr(LPADAPTER lpAdapter, unsigned char *ether_addr) //coge mac local
{ 
  // * Variables * /
  ULONG            IoCtlBufferLength = (sizeof(PACKET_OID_DATA) + sizeof(ULONG) - 1);
  PPACKET_OID_DATA OidData;


  // * Memory allocation for PACKET_OID_DATA structure * /
  OidData = (struct _PACKET_OID_DATA *)malloc(IoCtlBufferLength);

  // * Set Oid to indicate our query * /
  OidData->Oid = OID_802_3_CURRENT_ADDRESS;
  OidData->Length = 6;

  // * Query the adapter for his MAC address * /    
  if(PacketRequest(lpAdapter, FALSE, OidData) == FALSE) {
	if((ether_addr) == NULL) {
      printf("\n+ Ethernet address of adapter : 00-00-00-00-00-00\n");     
	}
	else {
     printf("\n**Interfaz erronea"); //memcpy(ether_addr, 0, 6);  //ya no peta al seleccionar interfaz invalida
	 printf("\n");
	}	
  }
  else {    	  
	if((ether_addr) == NULL) {
//      printf("\n+ Ethernet address of adapter : %02X-%02X-%02X-%02X-%02X-%02X\n",
//            (OidData->Data)[0], (OidData->Data)[1], (OidData->Data)[2],
//		    (OidData->Data)[3], (OidData->Data)[4], (OidData->Data)[5]);
	  printf("%02X-%02X-%02X-%02X-%02X-%02X",
            (OidData->Data)[0], (OidData->Data)[1], (OidData->Data)[2],
		    (OidData->Data)[3], (OidData->Data)[4], (OidData->Data)[5]);
	}
	else {	  
      memcpy(ether_addr, OidData->Data, 6);	  
	}
  } 
  // * Free buffer * /
  free(OidData);
}


void print_start(unsigned char *dst_etheraddr, unsigned char *src_etheraddr, 
              int ar_op, unsigned char *ar_sha, unsigned char *ar_sip,
              unsigned char *ar_tha, unsigned char *ar_tip) 
{//Informacion de los paquetes mandados en arp request o reply:

/*
  // * Print Ethernet header informations * /
  printf("\nDestination MAC : %02X-%02X-%02X-%02X-%02X-%02X\n", 
	      dst_etheraddr[0], dst_etheraddr[1], dst_etheraddr[2], 
	      dst_etheraddr[3], dst_etheraddr[4], dst_etheraddr[5]);	
 
  printf("Source MAC      : %02X-%02X-%02X-%02X-%02X-%02X\n", 
	      src_etheraddr[0], src_etheraddr[1], src_etheraddr[2], 
	      src_etheraddr[3], src_etheraddr[4], src_etheraddr[5]);		  
  

  // * Print ARP informations * /
  if(ar_op == 1) printf("+ ARP - ARP Request\n");
  else printf("+ ARP - ARP Reply\n");
  
  printf("+ ARP - Sender MAC address : %02X-%02X-%02X-%02X-%02X-%02X\n", 
	      ar_sha[0], ar_sha[1], ar_sha[2], 
	      ar_sha[3], ar_sha[4], ar_sha[5]);	
          
  printf("+ ARP - Sender IP address  : %d.%d.%d.%d\n", 
	       ar_sip[0], ar_sip[1], ar_sip[2], 
	       ar_sip[3]);

  printf("+ ARP - Target MAC address : %02X-%02X-%02X-%02X-%02X-%02X\n", 
	      ar_tha[0], ar_tha[1], ar_tha[2], 
	      ar_tha[3], ar_tha[4], ar_tha[5]);	

  printf("+ ARP - Target IP address  : %d.%d.%d.%d\n\n", 
	       ar_tip[0], ar_tip[1], ar_tip[2], 
	       ar_tip[3]);
*/

}


void statistics(int count)
{
  printf("  + %d packets transmitted (each: %d bytes - total: %d bytes)\n", count, sizeof(struct arp_packet), count * sizeof(struct arp_packet));
}


int get_remote_mac(LPADAPTER lpAdapter, unsigned char *iptarget, unsigned char *remotemac, int mode)
{
	char byteaux[3];

  // * WinPcap * /
  LPPACKET lpPacketRequest;
  LPPACKET lpPacketReply;
  char     buffer[256000];

  // * Packet * /
  struct arp_packet arp_pkt;
  unsigned char broadcast[ETH_ADD_LEN];
  unsigned char macsender[ARP_ETH_ADD_SPACE];  
  unsigned char mactarget[ARP_ETH_ADD_SPACE];
  unsigned char	ipsender[ARP_IP_ADD_SPACE];  

  // * Others * /
  int send_ok = 0;
  DWORD timestamp = 0;


  // * Init fields * /
  memset(broadcast, 0xFF, 6);
  memset(mactarget, 0, 6);  
  
  get_ether_addr(lpAdapter, macsender);
  transforma_a_ipU(ipeq,ipsender);
  
  // * Allocate PACKET structure for ARP Request packet * /
  if((lpPacketRequest = PacketAllocatePacket()) == NULL) {
    fprintf(stderr, "\nError : failed to allocate the LPPACKET structure.\n");

    return(EXIT_FAILURE);
  }  

  // * Init packet structure * /
  memset(&arp_pkt, 0, sizeof(struct arp_packet));          

  // * Build ARP Request packet * /
  arp_build(&arp_pkt, broadcast, macsender, ARP_OP_REQUEST, macsender, ipsender, mactarget, iptarget);     
 
  // * Init ARP Request packet * /
  PacketInitPacket(lpPacketRequest, &arp_pkt, sizeof(arp_pkt));
		
  // * Set number of ARP Request packets to send * /
  if(PacketSetNumWrites(lpAdapter, 1) == FALSE) {
    fprintf(stderr, "\nWarning : unable to send more than one packet in a single write.\n");
  }
   	  

  // * Set hardware filter to directed mode * /
  if(PacketSetHwFilter(lpAdapter, NDIS_PACKET_TYPE_DIRECTED) == FALSE){
    printf("\nWarning: unable to set directed mode.\n");	
  }

  // * Set a 512K buffer in the driver * /
  if(PacketSetBuff(lpAdapter, 512000) == FALSE){
    printf("\nError: unable to set the kernel buffer.\n");
	PacketFreePacket(lpPacketRequest);

	return(EXIT_FAILURE);
  }

  // * Set a 1 second read timeout * /
  if(PacketSetReadTimeout(lpAdapter, -1) == FALSE){
    printf("\nWarning: unable to set the read tiemout.\n");
  }
  
  // * Allocate PACKET structure for ARP Reply packet * /
  if((lpPacketReply = PacketAllocatePacket()) == NULL){
    printf("\nError: failed to allocate the LPPACKET structure.\n");
	PacketFreePacket(lpPacketRequest);

	return(EXIT_FAILURE);
  }
  
  // * Init ARP Reply packet * /
  PacketInitPacket(lpPacketReply, (char*)buffer, 256000);

  // * Allocate memory for remote MAC address * /
  if(mode == 1) {
    remotemac = (unsigned char*)malloc(sizeof(unsigned char) * 6);
  }

  timestamp = GetTickCount();

  // * Main capture loop * /
  while(1) {
    if(send_ok != 1) {
	  // * Send packet * /    
      if(PacketSendPacket(lpAdapter, lpPacketRequest, TRUE) == FALSE) { //si falló el envío vuelve a intentarlo
		  if(PacketSendPacket(lpAdapter, lpPacketRequest, TRUE) == FALSE) {
			fprintf(stderr, "\nError : unable to send the packets.\n");	                
			PacketFreePacket(lpPacketRequest);
			PacketFreePacket(lpPacketReply);

			return(EXIT_FAILURE);
		  }
	  }

      // * Free packet * /
      PacketFreePacket(lpPacketRequest);
      send_ok = 1;
	}
  
    // * Capture the packets * /
	if(PacketReceivePacket(lpAdapter, lpPacketReply, TRUE) == FALSE) { //si falla la recepcion lo vuelve a intentar
			if(PacketReceivePacket(lpAdapter, lpPacketReply, TRUE) == FALSE) {
				  printf("\nError: PacketReceivePacket failed.\n");      
				  PacketFreePacket(lpPacketReply);

				  return(EXIT_FAILURE);
		}
	}
    	
    if(lpPacketReply->ulBytesReceived > 0) {  
	  if(read_arp_reply(lpPacketReply, iptarget, remotemac) == EXIT_SUCCESS) {
		
		if(mode == 1) {		//Devuelve mac a partir de ip (la guarda en macaux)

			sprintf(byteaux, "%02X", remotemac[0]);
		    strcpy(macaux,byteaux);
			strcat(macaux,"-");
			sprintf(byteaux, "%02X", remotemac[1]);
			strcat(macaux,byteaux);
			strcat(macaux,"-");
			sprintf(byteaux, "%02X", remotemac[2]);
			strcat(macaux,byteaux);
			strcat(macaux,"-");
			sprintf(byteaux, "%02X", remotemac[3]);
			strcat(macaux,byteaux);
			strcat(macaux,"-");
			sprintf(byteaux, "%02X", remotemac[4]);
			strcat(macaux,byteaux);
			strcat(macaux,"-");
			sprintf(byteaux, "%02X", remotemac[5]);
			strcat(macaux,byteaux);
		}
	  
	    break;
	  }
	}	

	if((GetTickCount() - timestamp) > TIEMPO_PKT) {	//no se encontro mac para este host
      printf("\t* %d.%d.%d.%d offline", 
	            iptarget[0], iptarget[1], iptarget[2], iptarget[3]);    

	  return(EXIT_FAILURE);
	}
  }

  if(mode == 1) {
	  free(remotemac);
  }

  // * Free packet * /
  PacketFreePacket(lpPacketReply);  

  return(EXIT_SUCCESS);
}


int read_arp_reply(LPPACKET lpPacket, unsigned char *iptarget, unsigned char *result)
{
  // * Variables * /    
  unsigned short int ether_type;
  unsigned char      ipsender[4];   
  unsigned int       off=0;
  unsigned int       tlen, tlen1;      
  struct bpf_hdr     *hdr;		
  char	             *pChar;
  char	             *buf;
  

  // * Initialization * /  
  off = 0;

  // * Init buffer with packet data * /
  buf = (char *)lpPacket->Buffer;		
  
  // * Read packet * /	
  hdr = (struct bpf_hdr *)(buf + off);
  tlen1 = hdr->bh_datalen;
  tlen = hdr->bh_caplen;
  off += hdr->bh_hdrlen;	  
  pChar = (char*)(buf + off);	
  off = Packet_WORDALIGN(off + tlen);
	    
  // * Read Ethernet type * /
  memcpy(&ether_type, pChar + 12, 2); 
  ether_type = ntohs(ether_type);  

  if(ether_type == ETH_TYPE_ARP) {
    // * Copy ip address of sender * /
    memcpy(ipsender, pChar + 28, 4);	  	

    if((iptarget[0] == ipsender[0])&&(iptarget[1] == ipsender[1])&&
       (iptarget[2] == ipsender[2])&&(iptarget[3] == ipsender[3])) {
     
      // * Copy MAC address of sender * /
      memcpy(result, pChar + 22, 6);		        
	}
    else {

      return(EXIT_FAILURE);
	}  
  }
  else {

    return(EXIT_FAILURE);
  }
  return(EXIT_SUCCESS);
} 


int get_ip_addr(unsigned char *ip_addr)	//saca la ip del equipo local
{
	char byteipaux[4];
  // * Winsock * /
  WORD		    wVersionRequested; 
  WSADATA		wsaData; 
 
  // * Others * /
  char           hostname[256];
  struct hostent *info;
  unsigned char  ipaddr[4];
 

  wVersionRequested = MAKEWORD(1, 1); 
  if(WSAStartup(wVersionRequested, &wsaData) != 0) {
    fprintf(stderr, "\nError: unable to start WinSock\n");

    return(EXIT_FAILURE);
  }

  if(gethostname(hostname, 256) == SOCKET_ERROR) { // si falla lo vuelve a intentar
	    if(gethostname(hostname, 256) == SOCKET_ERROR) {
			fprintf(stderr, "\nError: unable to get ip address\n");
			WSACleanup();

			return(EXIT_FAILURE);
		}
  }


	if((info = gethostbyname(hostname)) != NULL) 
	{
		memcpy(ipaddr, (unsigned char *)(*info->h_addr_list), 4);

		if(ip_addr != NULL) 
		{
			memcpy(ip_addr, ipaddr, 4);
		}
		else	//Devuelve ip del equipo local (guardada en ipeq)
		{	
			itoa (ipaddr[0],byteipaux,10);
			strcpy( ipeq, byteipaux );
			strcat(ipeq,".");

			itoa (ipaddr[1],byteipaux,10);
			strcat(ipeq,byteipaux);
			strcat(ipeq,".");

			itoa (ipaddr[2],byteipaux,10);
			strcat(ipeq,byteipaux);
			strcat(ipeq,".");

			itoa (ipaddr[3],byteipaux,10);
			strcat(ipeq,byteipaux);
		}
	}
	else 
	{
		fprintf(stderr, "\nError: unable to get ip address\n");
		WSACleanup();

		return(EXIT_FAILURE);
	}

  WSACleanup();
  return(EXIT_SUCCESS);
}






// * /////////        GET ATTACK:         /////////  * /






int get_attack_mac(LPADAPTER lpAdapter, unsigned char *iptarget, unsigned char *remotemac, int mode, unsigned tiempo_esp)
{
	char byteaux[3];

  // * WinPcap * /
  LPPACKET lpPacketRequest;
  LPPACKET lpPacketReply;
  char     buffer[256000];

  // * Packet * /
  struct arp_packet arp_pkt;
  unsigned char broadcast[ETH_ADD_LEN];
  unsigned char macsender[ARP_ETH_ADD_SPACE];  
  unsigned char mactarget[ARP_ETH_ADD_SPACE];
  unsigned char	ipsender[ARP_IP_ADD_SPACE];  

  // * Others * /
  int send_ok = 0;
  DWORD timestamp = 0;


  // * Init fields * /
  memset(broadcast, 0xFF, 6);
  memset(mactarget, 0, 6);  
  
  get_ether_addr(lpAdapter, macsender);//coge mac local
  transforma_a_ipU(ipeq,ipsender);	   //coge ip  local
  
  // * Allocate PACKET structure for ARP Request packet * /
  if((lpPacketRequest = PacketAllocatePacket()) == NULL) {
    fprintf(stderr, "\nError : failed to allocate the LPPACKET structure.\n");

    return(EXIT_FAILURE);
  }  

  // * Init packet structure * /
  memset(&arp_pkt, 0, sizeof(struct arp_packet));          

  // * Build ARP Request packet * /
  arp_build(&arp_pkt, broadcast, macsender, ARP_OP_REQUEST, macsender, ipsender, mactarget, iptarget);     
 

		 // * Init ARP Request packet * /
//NO LO ENVIAMOS // PacketInitPacket(lpPacketRequest, &arp_pkt, sizeof(arp_pkt));


  // * Set number of ARP Request packets to send * /
  if(PacketSetNumWrites(lpAdapter, 1) == FALSE) {
    fprintf(stderr, "\nWarning : unable to send more than one packet in a single write.\n");
  }
   	  

  // * Set hardware filter to directed mode * /
  if(PacketSetHwFilter(lpAdapter, NDIS_PACKET_TYPE_DIRECTED) == FALSE){
    printf("\nWarning: unable to set directed mode.\n");	
  }

  // * Set a 512K buffer in the driver * /
  if(PacketSetBuff(lpAdapter, 512000) == FALSE){
    printf("\nError: unable to set the kernel buffer.\n");
	PacketFreePacket(lpPacketRequest);

	return(EXIT_FAILURE);
  }

  // * 10 segundos de espera de lectura * /
  if(PacketSetReadTimeout(lpAdapter, tiempo_esp) == FALSE){
    printf("\nWarning: unable to set the read tiemout.\n");
  }
  /*
  -Parametros:
    AdapterObject 	Pointer to an _ADAPTER structure.
    timeout 	indicates the timeout, in milliseconds, after which a call to PacketReceivePacket() 
				on the adapter pointed by AdapterObject will be released, also if no packets have been 
				captured by the driver. Setting timeout to 0 means no timeout, i.e. PacketReceivePacket() 
				never returns if no packet arrives. A timeout of -1 causes PacketReceivePacket() to always 
				return immediately.		http://dog.tele.jp/winpcap/html/Packet32_8c.html#a36
	*/
  

  // * Allocate PACKET structure for ARP Reply packet * /
  if((lpPacketReply = PacketAllocatePacket()) == NULL){
    printf("\nError: failed to allocate the LPPACKET structure.\n");
	PacketFreePacket(lpPacketRequest);

	return(EXIT_FAILURE);
  }
  
  // * Init ARP Reply packet * /
  PacketInitPacket(lpPacketReply, (char*)buffer, 256000);

  // * Allocate memory for remote MAC address * /
  if(mode == 1) {
    remotemac = (unsigned char*)malloc(sizeof(unsigned char) * 6);
  }

  timestamp = GetTickCount();

  // * Main capture loop * /

  while(1) {
PacketFreePacket(lpPacketRequest);

    // * Capture the packets * /
	if(PacketReceivePacket(lpAdapter, lpPacketReply, TRUE) == FALSE) { //si falla la recepcion lo vuelve a intentar
			if(PacketReceivePacket(lpAdapter, lpPacketReply, TRUE) == FALSE) {
				  printf("\nError: PacketReceivePacket failed.\n");      
				  PacketFreePacket(lpPacketReply);

				  return(EXIT_FAILURE);
		}
	}
    	
    if(lpPacketReply->ulBytesReceived > 0) {  
	  if(read_arp_reply(lpPacketReply, iptarget, remotemac) == EXIT_SUCCESS) {
		
		if(mode == 1) {		//Devuelve mac a partir de ip (la guarda en macaux)

			sprintf(byteaux, "%02X", remotemac[0]);
		    strcpy(macaux,byteaux);
			strcat(macaux,"-");
			sprintf(byteaux, "%02X", remotemac[1]);
			strcat(macaux,byteaux);
			strcat(macaux,"-");
			sprintf(byteaux, "%02X", remotemac[2]);
			strcat(macaux,byteaux);
			strcat(macaux,"-");
			sprintf(byteaux, "%02X", remotemac[3]);
			strcat(macaux,byteaux);
			strcat(macaux,"-");
			sprintf(byteaux, "%02X", remotemac[4]);
			strcat(macaux,byteaux);
			strcat(macaux,"-");
			sprintf(byteaux, "%02X", remotemac[5]);
			strcat(macaux,byteaux);
		}
	  
	    break;
	  }
	}	

	if((GetTickCount() - timestamp) > tiempo_esp) {	//en 15 segundos no hubo ningun ataque hacia el host local
		if(!primera_vez) 
		{
			printf("[-] El gw %d.%d.%d.%d no ha sido atacado en estos %d segs", 
	            iptarget[0], iptarget[1], iptarget[2], iptarget[3],tiempo_esp/1000);
		}
	  return(2);
	}
  }

  if(mode == 1) {
	  free(remotemac);
  }

  // * Free packet * /
  PacketFreePacket(lpPacketReply);  

  return(EXIT_SUCCESS);
}