
#ifndef _UMIP_ARP_H_
#define _UMIP_ARP_H_

#include "mac.h"

#define ARP_ENTRIES 8

typedef struct {
  uint16_t wHwType;
  uint16_t wProtoType;
  uint8_t cHwSize;
  uint8_t cProtoSize;
  uint16_t wOperation;
  MacAddr srcAddr;
  Ip4Addr srcIpAddr;
  MacAddr destAddr;
  Ip4Addr destIpAddr;
} __attribute__((packed)) ArpPacket;

typedef struct {
  Ip4Addr addr;
  MacAddr macAddr;
  uint16_t wFlags;
} ArpEntry;

typedef struct {
  ArpEntry local;
  ArpEntry table[ARP_ENTRIES];
  uint8_t nentries;
  MacDevice *mdev;
} ArpHandler;

#define ARP_HWTYPE_ETHER 0x0001

#define ARP_PROTOTYPE_IP4 0x0800

#define ARP_OP_REQUEST 0x0001
#define ARP_OP_REPLY   0x0002

void arp_init(ArpHandler *, MacDevice *);
void arp_set_self(ArpHandler *, MacAddr, Ip4Addr);
uint8_t arp_handle_msg(ArpHandler *);
void arp_add_entry(ArpHandler *, MacAddr, Ip4Addr);
uint8_t arp_get_addr(ArpHandler *, MacAddr, Ip4Addr);
void arp_send_request(ArpHandler *, Ip4Addr);

#endif // _UMIP_ARP_H_
