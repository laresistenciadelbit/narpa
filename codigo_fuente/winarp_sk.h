#ifndef _WINARP_SK_H_
#define _WINARP_SK_H_

#define RELEASE_VERSION "1.7"

/* Ethernet header */
#define	ETH_TYPE_ARP     0x0806  /* Ether type ARP            */
#define ETH_ADD_LEN      6       /* Ethernet address length   */
#define ETH_PADDING_ARP  18      /* 18 bytes ethernet padding */

/* ARP header */
#define ARP_HW_ETH         1     /* Hardware type 10Mb Ethernet */
#define ARP_PRO_IP         0x800 /* ARP Protocol IP             */
#define ARP_ETH_ADD_SPACE  6     /* Ethernet address length     */
#define ARP_IP_ADD_SPACE   4     /* IP address length           */
#define ARP_OP_REQUEST     1     /* ARP request                 */
#define ARP_OP_REPLY       2     /* ARP reply                   */

struct arp_packet {
  /* Ethernet header */
  unsigned char      eth_dst_addr[ETH_ADD_LEN]; /* Destination ethernet address	        */
  unsigned char      eth_src_addr[ETH_ADD_LEN]; /* Source ethernet address              */
  unsigned short int eth_type;                  /* EtherType                            */

  /* ARP header */
  unsigned short int ar_hrd;                    /* Hardware address space               */
  unsigned short int ar_pro;                    /* Protocol address space               */
  unsigned char      ar_hln;                    /* byte length of each hardware address */
  unsigned char      ar_pln;                    /* byte length of each protocol address */
  unsigned short int ar_op;                     /* ARP opcode                           */
  unsigned char      ar_sha[ARP_ETH_ADD_SPACE]; /* Sender hardware address              */
  unsigned char      ar_spa[ARP_IP_ADD_SPACE];  /* Sender protocol address              */
  unsigned char      ar_tha[ARP_ETH_ADD_SPACE]; /* Target hardware address              */
  unsigned char      ar_tpa[ARP_IP_ADD_SPACE];  /* Target protocol address              */

  /* Ethernet padding */
  unsigned char      eth_pad[ETH_PADDING_ARP];  /* Ethernet padding                     */
};


/* Prototype */

void usage();
void get_ether_addr(LPADAPTER, unsigned char *);
int get_ip_addr(unsigned char *);
void statistics(int);
int get_remote_mac(LPADAPTER, unsigned char *, unsigned char *, int);
int read_arp_reply(LPPACKET, unsigned char *, unsigned char *);
int	 arp_build(struct arp_packet *, unsigned char *, unsigned char *, int, 
			   unsigned char *, unsigned char *, unsigned char *, 
			   unsigned char *);
void print_start(unsigned char *, unsigned char *, int, unsigned char *, 
                  unsigned char *, unsigned char *, unsigned char *);

#endif /* _WINARP_SK_H_ */