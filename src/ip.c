
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
