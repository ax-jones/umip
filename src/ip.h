
#ifndef _UMIP_IP_H_
#define _UMIP_IP_H_

#include "mac.h"
#include "arp.h"

typedef uint16_t IpPort;

typedef struct {
  MacHeader mac;
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

#define IP_VERS_IPV4 0x45
#define IP_VERS_IPV6 0x60

#define IP_HEADER_LEN 0x04

#define IP_DSF_DEFAULT 0x00

#define IP_FLAGS_MORE_FRAGMENTS 0x8000
#define IP_FLAGS_DONT_FRAGMENT 0x4000

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

void udp_init_hdr(UdpHeader *uph, Ip4Addr srcAddr, IpPort srcPort, Ip4Addr destAddr, IpPort destPort);

typedef struct {
  Ip4Addr remoteAddr;
  IpPort remotePort;
  IpPort localPort;
  uint32_t localSeqNumber;
  uint32_t remoteSeqNumber;
  uint8_t sessionState;
} __attribute__((packed)) TcpSession;

typedef struct {
  Ip4Addr localAddr;
  Ip4Addr gatewayAddr;
  uint8_t netmask;
  MacDevice *mdev;
  ArpHandler arph;
  TcpSession tcpSessions[8];
  uint8_t nSessions;
} IpHost;

#define IPV4_ADDR_NULL 0x0;

#define IPV4_ADDR(a,b,c,d) ((a << 24) | (b << 16) | (c << 8) | d)

void iph_init(IpHost *iph, MacDevice *mdev);
uint8_t iph_proc(IpHost *iph);
uint8_t iph_handle_msg(IpHost *iph);
void iph_set_ip4addr(IpHost *, Ip4Addr localAddr, Ip4Addr netmask);

IpHeader *iph_get_ip_header(MacFrame *mf);
IpHeader *iph_init_head(IpHost *iph, Ip4Addr dest);
void iph_finish_frame(MacFrame *mf, IpHeader *iphead, uint16_t len);

uint16_t ip_calc_csum(uint16_t *ptr, uint16_t len);

uint8_t udp_handle_msg(IpHost *iph);

typedef struct {
  IpHeader ipHead;
  IpPort srcPort;
  IpPort destPort;
  uint32_t seqNumber;
  uint32_t ackNumber;
  uint8_t offset;
  uint8_t tcpFlags;
  uint16_t window;
  uint16_t tcpChecksum;
  uint16_t urgentPtr;
} __attribute__((packed)) TcpHeader;

uint8_t tcp_handle_msg(IpHost *);

void tcp_init_hdr(TcpHeader *tcph, Ip4Addr srcAddr, IpPort srcPort, Ip4Addr destAddr, IpPort destPort);
void tcp_finish_frame(MacFrame *mf, TcpHeader *tcph, uint16_t len);

void tcp_create_session(IpHost *iph, Ip4Addr destAddr, IpPort destPort);
void tcp_send_ack(IpHost *iph, TcpSession *tcps);
void tcp_handle_frame(IpHost *iph, TcpHeader *tcph);
void tcp_close_session(IpHost *iph, TcpSession *tcps);

TcpSession *tcp_get_session(IpHost *iph, Ip4Addr remoteAddr, IpPort remotePort);
TcpHeader *tcp_get_header(MacFrame *mf);

#endif // _UMIP_IP_H_
