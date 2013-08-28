
#include <stdint.h>
#include <stdio.h>
#include "arp.h"

void arp_init(ArpHandler *ah, MacDevice *mdev)
{
  ah->nentries = 0;
  ah->mdev = mdev;
}

void arp_set_self(ArpHandler *ah, MacAddr localMac, Ip4Addr localIp)
{
  ah->local.addr = HTONL(localIp);
  _memcpy(ah->local.macAddr, localMac, MAC_ADDR_LEN);
}

uint8_t arp_handle_msg(ArpHandler *ah)
{
  ArpPacket *ap = (ArpPacket*)mac_frame_payload(&ah->mdev->recvFrame);

  if(ap->wOperation == HTONS(ARP_OP_REQUEST)) {
    ArpPacket rep;
    rep.wHwType = HTONS(ARP_HWTYPE_ETHER);
    rep.wProtoType = HTONS(ARP_PROTOTYPE_IP4);
    rep.cHwSize = MAC_ADDR_LEN;
    rep.cProtoSize = 4;
    rep.wOperation = HTONS(ARP_OP_REPLY);
    _memcpy(rep.srcAddr, ah->local.macAddr, MAC_ADDR_LEN);
    rep.srcIpAddr = ah->local.addr;
    _memcpy(rep.destAddr, ap->srcAddr, MAC_ADDR_LEN);
    rep.destIpAddr = ap->destIpAddr;

    mac_clear_frame(&ah->mdev->sendFrame);
    mac_init_frame(ah->mdev, ap->srcAddr, MAC_FRAME_TYPE_ARP);
    mac_write_frame(&ah->mdev->sendFrame, (uint8_t*)&rep, sizeof(rep), 0);

    dout("Got an arp req from %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.\n", rep.srcAddr[0], rep.srcAddr[1], rep.srcAddr[2], rep.srcAddr[3], rep.srcAddr[4], rep.srcAddr[5]);
    return 1;
  } else if(ap->wOperation == HTONS(ARP_OP_REPLY)) {
    arp_add_entry(ah, ap->srcAddr, ap->srcIpAddr);
  }
  return 0;
}

uint8_t arp_get_addr(ArpHandler *ah, MacAddr macaddr, Ip4Addr ipaddr)
{
  int i;
  for(i = 0; i < ah->nentries; i++) {
    if(ah->table[i].addr == ipaddr) {
      _memcpy(macaddr, ah->table[i].macAddr, MAC_ADDR_LEN);
      return 1;
    }
  }
  return 0;
}

void arp_add_entry(ArpHandler *ah, MacAddr macaddr, Ip4Addr ipaddr)
{
  if(ah->nentries < ARP_ENTRIES) {
    ah->table[ah->nentries].addr = ipaddr;
    _memcpy(ah->table[ah->nentries].macAddr, macaddr, MAC_ADDR_LEN);
    ah->nentries++;
  }
}

void arp_send_request(ArpHandler *ah, Ip4Addr ipaddr)
{
  ArpPacket req;

  req.wHwType = HTONS(ARP_HWTYPE_ETHER);
  req.wProtoType = HTONS(ARP_PROTOTYPE_IP4);
  req.cHwSize = MAC_ADDR_LEN;
  req.cProtoSize = 4;
  req.wOperation = ARP_OP_REQUEST;
  _memcpy(req.srcAddr, ah->local.macAddr, MAC_ADDR_LEN);
  req.srcIpAddr = ah->local.addr;
  req.destIpAddr = ipaddr;

  mac_clear_frame(&ah->mdev->sendFrame);
  mac_init_frame_bcast(ah->mdev, MAC_FRAME_TYPE_ARP);
  mac_write_frame(&ah->mdev->sendFrame, (uint8_t*)&req, sizeof(req), 0);
}
