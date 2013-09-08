
#ifndef _UMIP_ICMP_H_
#define _UMIP_ICMP_H_

#include "ip.h"

enum IcmpType { icmpEchoReply, icmpUnreachable = 3, icmpSourceQuench, icmpRedirect, icmpEchoRequest = 8, icmpTraceRoute = 30 };

typedef struct {
  IpHeader ipHead;
  uint8_t cType;
  uint8_t cCode;
  uint16_t wChecksum;
  uint32_t headData;
} __attribute__((packed)) IcmpHeader;

uint8_t icmp_handle_msg(IpHost *iph);
IcmpHeader *icmp_get_header(MacFrame *mf);
void icmp_finish_frame(MacFrame *mf, IcmpHeader *icmph, uint16_t len);

uint8_t *icmp_payload(IcmpHeader *icmph);
uint16_t icmp_paylen(IcmpHeader *icmph);

#endif // _UMIP_ICMP_H_
