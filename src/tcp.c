
#include <stdint.h>
#include <stdio.h>
#include "ip.h"

const char htstr[] = "HTTP/1.1 200 OK\nDate: Sat, 07 Sep 2013 15:25:32 GMT\nContent-Length: 45\nContent-Type: text/html\n\n<html><body><h1>It works!</h1></body></html>\n";

uint8_t tcp_handle_msg(IpHost *iph)
{
  TcpFrame *tcprf = tcp_get_header(&iph->mdev->recvFrame);
  TcpHeader *tcprh = &tcprf->tcpHead;

  if(tcprh->tcpFlags & TCP_SYN) {
    dout("new connection from %hhx %08x %i to %i.\n", tcprh->tcpFlags, HTONL(tcprf->ipHead.srcAddr), HTONS(tcprh->srcPort), HTONS(tcprh->destPort));
    TcpSession *tcps = tcp_create_session(iph, tcprf->ipHead.srcAddr, tcprh->srcPort, tcprh->destPort);

    if(!arp_has_addr(&iph->arph, tcprf->ipHead.srcAddr))
      arp_add_entry(&iph->arph, tcprf->ipHead.mac.srcAddr, tcprf->ipHead.srcAddr);
    tcps->remoteSeqNumber = HTONL(tcprh->seqNumber) + 1;

    TcpFrame *tcpsf = tcp_init_head(iph, tcps);
    TcpHeader *tcpsh = &tcpsf->tcpHead;
    tcpsh->tcpFlags = TCP_SYN | TCP_ACK;
    tcp_finish_frame(&iph->mdev->sendFrame, tcpsf, 0);

    return 1;
  }
  if(tcprh->tcpFlags & TCP_PSH) {
    TcpSession *tcps = tcp_get_session(iph, tcprf->ipHead.srcAddr, tcprf->tcpHead.srcPort, tcprf->tcpHead.destPort);

    TcpFrame *tcpsf = tcp_init_head(iph, tcps);
    TcpHeader *tcpsh = &tcpsf->tcpHead;
    uint8_t *dptr = tcp_get_payload(tcpsf);
    tcpsh->tcpFlags = TCP_PSH | TCP_ACK;

    uint16_t l = _strlen(htstr) + 1;
    _memcpy(dptr, htstr, l);
    tcp_finish_frame(&iph->mdev->sendFrame, tcpsf, l);

    return 1;
  }

  dout("tcp-wtf? %x %x %i %i\n", tcprh->tcpFlags, HTONL(tcprf->ipHead.srcAddr), HTONS(tcprh->srcPort), HTONS(tcprh->destPort));
#if 1
  uint8_t *prbuf = iph->mdev->recvFrame.packet;
  int len = iph->mdev->recvFrame.writePtr, i;
    for(i = 0; i < len; i++) {
      dout("%02hhx ", *(prbuf++));
    }
#endif
  return 0;
}

TcpFrame *tcp_get_header(MacFrame *mf)
{
  return (TcpFrame *)mf->packet;
}

TcpFrame *tcp_init_head(IpHost *iph, TcpSession *tcps)
{
  TcpFrame *tcpf = (TcpFrame*) iph_init_head(iph, tcps->remoteAddr);
  TcpHeader *tcph = &tcpf->tcpHead;

  tcph->srcPort = tcps->localPort;
  tcph->destPort = tcps->remotePort;
  tcph->seqNumber = HTONL(tcps->localSeqNumber++);
  tcph->ackNumber = HTONL(tcps->remoteSeqNumber);
  tcph->offset = 5 << 4;
  tcph->window = HTONS(1400);
  tcph->urgentPtr = 0;
  tcph->tcpChecksum = 0;
  tcpf->ipHead.cProtocol = IP_PROTO_TCP;
}

TcpSession *tcp_create_session(IpHost *iph, Ip4Addr remoteAddr, IpPort remotePort, IpPort localPort)
{
  TcpSession *tcps = &iph->tcpSessions[iph->nSessions++];

  tcps->remoteAddr = remoteAddr;
  tcps->remotePort = remotePort;
  tcps->localPort = localPort;
  tcps->localSeqNumber = 1;

  return tcps;
}

void tcp_finish_frame(MacFrame *mf, TcpFrame *tcpf, uint16_t len)
{
  TcpCsum tcpsum;

  tcpsum.tcpHeader = tcpf->tcpHead;
  tcpsum.srcAddr = tcpf->ipHead.srcAddr;
  tcpsum.destAddr = tcpf->ipHead.destAddr;
  tcpsum.pad = 0;
  tcpsum.protocol = 6;
  tcpsum.tcpLen = HTONS(len + sizeof(TcpHeader));

  uint16_t csum = ip_calc_csum((uint16_t*) &tcpsum, sizeof(TcpCsum), 0);
  if(len) csum = ip_calc_csum((uint16_t*) tcp_get_payload(tcpf), len, ~csum);
  tcpf->tcpHead.tcpChecksum = csum;
  iph_finish_frame(mf, &tcpf->ipHead, len + sizeof(TcpHeader));
  dout("tcp csum %hx.\n", csum);
}

uint8_t *tcp_get_payload(TcpFrame *tcpf)
{
  uint8_t *dptr = (uint8_t*) tcpf;

  return dptr + sizeof(TcpFrame);
}

TcpSession *tcp_get_session(IpHost *iph, Ip4Addr remoteAddr, IpPort remotePort, IpPort localPort)
{
  uint8_t i = 0;
  while(i < iph->nSessions) {
    TcpSession *tcps = &iph->tcpSessions[i];
    if((tcps->remoteAddr == remoteAddr) && (tcps->remotePort == remotePort) && (tcps->localPort == localPort)) return tcps;
    i++;
  }
  return NULL;
}
