
#include <stdint.h>
#include <stdio.h>
#include "ip.h"

uint8_t tcp_handle_msg(IpHost *iph)
{
  TcpFrame *tcprf = tcp_get_header(&iph->mdev->recvFrame);
  TcpHeader *tcprh = &tcprf->tcpHead;

  if(tcprh->tcpFlags & TCP_SYN) {
    dout("new connection from %hhx %08x %i to %i.\n", tcprh->tcpFlags, HTONL(tcprf->ipHead.srcAddr), HTONS(tcprh->srcPort), HTONS(tcprh->destPort));
    TcpSession *tcps = tcp_create_session(iph, tcprf->ipHead.srcAddr, tcprh->srcPort, tcprh->destPort);

    tcps->remoteSeqNumber = HTONL(tcprh->seqNumber) + 1;

    TcpFrame *tcpsf = tcp_init_head(iph, tcps);
    TcpHeader *tcpsh = &tcpsf->tcpHead;
    tcpsh->tcpFlags = TCP_SYN | TCP_ACK;
    tcp_finish_frame(&iph->mdev->sendFrame, tcpsf, sizeof(TcpHeader));

    return 1;
  }

  return 0;
}

TcpFrame *tcp_get_header(MacFrame *mf)
{
  return (TcpFrame *)&mf->packet;
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
  tcpsum.tcpLen = HTONS(len);
  uint16_t csum = ip_calc_csum((uint16_t*)&tcpsum, sizeof(TcpCsum), 0);
  tcpf->tcpHead.tcpChecksum = csum;
  iph_finish_frame(mf, &tcpf->ipHead, len);
  dout("tcp csum %hx.\n", csum);
}
