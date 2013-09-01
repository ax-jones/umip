
#include <stdint.h>
#include <stdio.h>
#include "ip.h"

void iph_init(IpHost *iph, MacDevice *mdev)
{
  iph->mdev = mdev;
  iph->localAddr = IPV4_ADDR_NULL;
  iph->gatewayAddr = IPV4_ADDR_NULL;
  iph->netmask = 32;

  arp_init(&iph->arph, mdev);
}

uint8_t iph_proc(IpHost *iph)
{
  MacFrame *mf = &iph->mdev->recvFrame;
  MacHeader *mhdr = mac_frame_header(mf);

  if(mhdr->wType == HTONS(MAC_FRAME_TYPE_IP4)) {
    return iph_handle_msg(iph);
  } else if(mhdr->wType == HTONS(MAC_FRAME_TYPE_ARP)) {
    return arp_handle_msg(&iph->arph);
  } else if(mhdr->wType == HTONS(MAC_FRAME_TYPE_IP6)) {
    
  } else {
    dout("Error frame type %hx not recognized.\n", mhdr->wType);
  }
  return 0;
}

void iph_set_ip4addr(IpHost *iph, Ip4Addr addr, Ip4Addr netmask)
{
  iph->localAddr = addr;
  iph->netmask = netmask;

  arp_set_self(&iph->arph, iph->mdev->localAddr, addr);
}

uint8_t iph_handle_msg(IpHost *iph)
{
  IpHeader *iphead = iph_get_ip_header(&iph->mdev->recvFrame);

  switch(iphead->cProtocol) {
  case IP_PROTO_ICMP:
    return icmp_handle_msg(iph);
  case IP_PROTO_UDP:
    return udp_handle_msg(iph);
  case IP_PROTO_TCP:
    return tcp_handle_msg(iph);
  default:
    dout("Unknown protocol %i.\n", iphead->cProtocol);
    return 0;
  }
}

IpHeader *iph_get_ip_header(MacFrame *mf)
{
  return (IpHeader *)mf->packet;
}

IpHeader *iph_init_head(IpHost *iph, Ip4Addr dest)
{
  IpHeader *iphead = iph_get_ip_header(&iph->mdev->sendFrame);

  MacAddr destMac;

  if(!arp_get_addr(&iph->arph, destMac, dest)) {
    dout("Can't find mac for %x.\n", dest);
    return NULL;
  }

  mac_init_frame(iph->mdev, destMac, MAC_FRAME_TYPE_IP4);

  iphead->cVersion = IP_VERS_IPV4;
  iphead->cTos = 0;
  iphead->cTTL = 64;
  iphead->srcAddr = HTONL(iph->localAddr);
  iphead->destAddr = dest;
  iphead->wFragmentOff = 0;
  iphead->wIndent = 0;

  return iphead;
}

void iph_finish_frame(MacFrame *mf, IpHeader *iphead, uint16_t len)
{
  iphead->wHdrChecksum = 0;
  iphead->wTotalLen = HTONS((20 + len));

  uint8_t *ipp = (uint8_t*) iphead;
  ipp += sizeof(MacHeader);
  iphead->wHdrChecksum = ip_calc_csum((uint16_t*)ipp, sizeof(IpHeader) - sizeof(MacHeader));

  mf->writePtr = len + sizeof(IpHeader);

  dout("checksum for iph %hx.\n", iphead->wHdrChecksum);
}

uint16_t ip_calc_csum(uint16_t *ptr, uint16_t len)
{
  uint32_t sum = 0;

  while(len > 1) {
    sum += *(ptr++);
    len -= 2;
  }
  if(len) sum += *ptr & 0xff;

  while(sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

  return ~(uint16_t)(sum);
}

uint8_t udp_handle_msg(IpHost *iph)
{
  dout("udp msg received.\n");
  return 0;
}
