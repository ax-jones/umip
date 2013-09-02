
#include <stdint.h>
#include <stdio.h>
#include "ip.h"

uint8_t tcp_handle_msg(IpHost *iph)
{
  TcpHeader *tcph = tcp_get_header(&iph->mdev->recvFrame);

  if(tcph->tcpFlags & TCP_SYN) {
    dout("new connection from %08x %i to %i.\n", HTONL(tcph->ipHead.srcAddr), HTONS(tcph->srcPort), HTONS(tcph->destPort));
  }

  return 0;
}

TcpHeader *tcp_get_header(MacFrame *mf)
{
  return (TcpHeader *)&mf->packet;
}
