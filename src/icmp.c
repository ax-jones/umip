
#include <stdint.h>
#include <stdio.h>
#include "icmp.h"

uint8_t icmp_handle_msg(IpHost *iph)
{
  IcmpHeader *ihead = icmp_get_header(&iph->mdev->recvFrame);

  if(ihead->cType == icmpEchoRequest) {
    if(!arp_has_addr(&iph->arph, ihead->ipHead.srcAddr)) {
      arp_add_entry(&iph->arph, ihead->ipHead.mac.srcAddr, ihead->ipHead.srcAddr);
    }
    IcmpHeader *shead = (IcmpHeader*) iph_init_head(iph, ihead->ipHead.srcAddr);

    shead->ipHead.cProtocol = IP_PROTO_ICMP;
    shead->cType = icmpEchoReply;
    shead->cCode = 0;
    shead->headData = ihead->headData;
    shead->ipHead.cTTL = ihead->ipHead.cTTL;

    dout("icmp msg %hu.\n", icmp_paylen(ihead));

    _memcpy(icmp_payload(shead), icmp_payload(ihead), icmp_paylen(ihead));
    icmp_finish_frame(&iph->mdev->sendFrame, shead, icmp_paylen(ihead) + 8);
    return 1;
  }

  return 0;
}

IcmpHeader *icmp_get_header(MacFrame *mf)
{
  return (IcmpHeader*)mf->packet;
}

void icmp_finish_frame(MacFrame *mf, IcmpHeader *icmph, uint16_t len)
{
  uint8_t *hp = (uint8_t*) icmph;

  icmph->wChecksum = 0;
  uint16_t csum = ip_calc_csum((uint16_t*) (hp+sizeof(IpHeader)), 8, 0);
  icmph->wChecksum = csum;

  dout("csum for icmp %hx %hu.\n", icmph->wChecksum, icmp_paylen(icmph));

  iph_finish_frame(mf, &icmph->ipHead, len);
}

uint8_t *icmp_payload(IcmpHeader *icmph)
{
  return ((uint8_t*)icmph) + sizeof(IcmpHeader);
}

uint16_t icmp_paylen(IcmpHeader *icmph)
{
  return (HTONS(icmph->ipHead.wTotalLen) + sizeof(MacHeader)) - sizeof(IcmpHeader);
}
