
#ifndef _UMIP_IP_H_
#define _UMIP_IP_H_

#include "mac.h"
#include "arp.h"

typedef uint16_t IpPort;

typedef struct {
  uint8_t cVersion;
  uint8_t cTos;
  uint16_t wTotalLen;
  uint16_t wIndent;
  uint16_t wFragmentOff;
  uint8_t cTTL;
  uint8_t cProtocol;
  uint16_t wHdrChecksum;
  Ip4Addr srcAddr;
  Ip4Addr destAddr;
  // uint32_t dIPOption;
} __attribute__((packed)) IpHeader;

#define IP_VERS_IPV4 0x40
#define IP_VERS_IPV6 0x60

#define IP_HEADER_LEN 0x04

#define IP_DSF_DEFAULT 0x00

#define IP_FLAGS_MORE_FRAGMENTS 0x20
#define IP_FLAGS_DONT_FRAGMENT 0x40

#define IP_PROTO_ICMP 0x01
#define IP_PROTO_TCP 0x06
#define IP_PROTO_UDP 0x11

void ip_init_hdr(IpHeader *iph, uint8_t protocol, Ip4Addr srcAddr, Ip4Addr destAddr);

typedef struct {
IpHeader;
IpPort wSrcPort;
IpPort wDestPort;
uint16_t wLength;
uint16_t wChecksum;
} __attribute__((packed)) UdpHeader;

void udp_init_hdr(UdpHeader *uph, IpPort srcPort, IpPort destPort, uint16_t len, uint16_t checksum);

typedef struct {
  Ip4Addr localAddr;
  Ip4Addr gatewayAddr;
  uint8_t netmask;
  MacDevice *mdev;
  ArpHandler arph;
} IpHost;

#define IPV4_ADDR_NULL 0x0;

void iph_init(IpHost *, MacDevice *mdev);
uint8_t iph_proc(IpHost *);
void iph_set_ip4addr(IpHost *, Ip4Addr, Ip4Addr);

#endif // _UMIP_IP_H_
