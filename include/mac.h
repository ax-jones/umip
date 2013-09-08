
#ifndef _UMIP_MAC_H_
#define _UMIP_MAC_H_

#include "common.h"

#define MAC_ADDR_LEN 6
#define PACKET_LEN 1500

/*typedef struct {
  uint8_t addr[MAC_ADDR_LEN];
} __attribute__((packed)) MacAddr;*/
typedef uint8_t MacAddr[MAC_ADDR_LEN];
typedef uint32_t Ip4Addr;

typedef struct {
  MacAddr destAddr;
  MacAddr srcAddr;
  uint16_t wType;
} __attribute__((packed)) MacHeader;

#define MAC_FRAME_TYPE_IP4 0x0800
#define MAC_FRAME_TYPE_ARP 0x0806
#define MAC_FRAME_TYPE_IP6 0x86dd

typedef struct {
  uint8_t packet[PACKET_LEN];
  uint16_t writePtr, readPtr;
  uint8_t flags;
} __attribute__((packed)) MacFrame;

typedef struct {
  MacFrame sendFrame, recvFrame;
  MacAddr localAddr;
} __attribute__((packed)) MacDevice;

/* client interface begin */

void mac_init(MacDevice *mac, uint8_t *addr);

void mac_write_frame(MacFrame *mf, uint8_t *packet, uint16_t len, uint8_t raw);
void mac_send_frame(MacFrame *);
void mac_read_frame(MacFrame *mf, uint8_t *packet, uint16_t len, uint8_t raw);
void mac_get_frame(MacFrame *);
void mac_clear_frame(MacFrame *);
void mac_init_frame(MacDevice *md, MacAddr dest, uint16_t proto);
void mac_init_frame_bcast(MacDevice *md, uint16_t proto);

#define FRAME_FILLING  0x01
#define FRAME_EMPTY    0x02
#define FRAME_READY    0x04
#define FRAME_BUSY     0x08

inline MacHeader *mac_frame_header(MacFrame *mf);
inline uint8_t *mac_frame_payload(MacFrame *mf);
inline uint16_t mac_payload_len(MacFrame *mf);

/* client interface end */

#endif // _UMIP_MAC_H_
