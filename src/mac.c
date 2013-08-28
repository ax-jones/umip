
#include <stdint.h>
#include "mac.h"

void mac_init(MacDevice *mdev, uint8_t *addr)
{
  uint8_t *laddr = mdev->localAddr, i;

  for(i = 0; i < 6; i++) *(laddr++) = *(addr++);

  mac_clear_frame(&mdev->recvFrame);
  mac_clear_frame(&mdev->sendFrame);

  _memcpy(mac_frame_header(&mdev->sendFrame)->srcAddr, addr, MAC_ADDR_LEN);
}

void mac_write_frame(MacFrame *mf, uint8_t *packet, uint16_t len, uint8_t raw)
{
  uint8_t *wptr = mf->packet + mf->writePtr;
  len += mf->writePtr;

  while(mf->writePtr++ < len) *(wptr++) = *(packet++);
}

void mac_send_frame(MacFrame *mf)
{
}

void mac_read_frame(MacFrame *mf, uint8_t *packet, uint16_t len, uint8_t raw)
{
  uint8_t *rptr = raw ? mf->packet : mac_frame_payload(mf);
  len += mf->readPtr + (raw ? 0 : sizeof(MacHeader));

  while(mf->readPtr++ < len) *(packet++) = *(rptr);
}

void mac_clear_frame(MacFrame *mf)
{
  mf->writePtr = mf->readPtr = 0;
  mf->flags = 0;
}

void mac_init_frame(MacDevice *md, MacAddr dest, uint16_t proto)
{
  MacHeader *mh = mac_frame_header(&md->sendFrame);

  _memcpy(mh->destAddr, dest, MAC_ADDR_LEN);
  _memcpy(mh->srcAddr, md->localAddr, MAC_ADDR_LEN);
  mh->wType = HTONS(proto);
  md->sendFrame.writePtr = sizeof(MacHeader);
}
void mac_init_frame_bcast(MacDevice *md, uint16_t proto)
{
  uint8_t bcast[6];
  _memset(bcast, 0xff, 6);
  mac_init_frame(md, bcast, proto);
}

MacHeader *mac_frame_header(MacFrame *mf)
{ return (MacHeader*) mf->packet; };
uint8_t *mac_frame_payload(MacFrame *mf)
{ return mf->packet + sizeof(MacHeader); };
uint16_t mac_payload_len(MacFrame *mf)
{ return mf->writePtr - sizeof(MacHeader); };
