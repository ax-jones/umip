
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include "utap.h"
#include "icmp.h"

void usage(const char *appName) { fprintf(stderr, "Usage: %s <if name>\n", appName); };

int main(int argc, char **argv)
{
  /*if(argc < 2) {
    usage(argv[0]);
    exit(-1);
   }*/

  MacDevice mdev;
  IpHost iph;
  char ifname[IFNAMSIZ], pktbuff[TAP_BUFFER_SIZE], pktlabel[16], outbuff[TAP_BUFFER_SIZE];

  ifname[0] = '\0';

  int tapfd = umip_open_tap(ifname), nread, outfd = -1;

  if(tapfd < 0) {
    exit(-1);
  }

  printf("Interface %s opened %lu %i %i %i.\n", ifname, sizeof(MacHeader), sizeof(IpHeader), sizeof(IcmpHeader), 0);

  if(argc == 2) {
    outfd = open(argv[1], O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IRGRP | S_IROTH);
    if(outfd < 0) perror("Opening dumpfile failed");
  }

  uint8_t macAddr[6] = { 0x24, 0x52, 0x81, 0x93, 0x19, 0x22 };
  mac_init(&mdev, macAddr);
  iph_init(&iph, &mdev);
  iph_set_ip4addr(&iph, (10 << 24) | (5 << 16) | (1 << 8) | 1, 0xffffffff);

  while(1) {
    nread = read(tapfd, pktbuff, TAP_BUFFER_SIZE);
    if(nread < 0) {
      perror("Reading from interface");
      close(tapfd);
      exit(-1);
    }
    mac_clear_frame(&mdev.recvFrame);
    mac_write_frame(&mdev.recvFrame, pktbuff, nread, 1);

    uint8_t *ra = mac_frame_header(&mdev.recvFrame)->srcAddr;
    printf("Pkt %i read from 0x%hhx%hhx%hhx%hhx%hhx%hhx %hx 0x%02hhx%02hhx%02hhx%02hhx.\n", mac_payload_len(&mdev.recvFrame), ra[0], ra[1], ra[2], ra[3], ra[4], ra[5], NTOHS(mac_frame_header(&mdev.recvFrame)->wType), pktbuff[0], pktbuff[1], pktbuff[2], pktbuff[3]);

    _memset(mdev.sendFrame.packet, 0, TAP_BUFFER_SIZE);

    if(iph_proc(&iph)) {
      dout("we write something %hi.\n", mac_payload_len(&mdev.sendFrame));
      //memcpy(outbuff, mdev.sendFrame.packet, mdev.sendFrame.writePtr);
      write(tapfd, mdev.sendFrame.packet, mdev.sendFrame.writePtr);
      mac_clear_frame(&mdev.sendFrame);
    }
    if(outfd > 0) {
      snprintf(pktlabel, 16, "\n%i:\n", mac_payload_len(&mdev.recvFrame));
      //write(outfd, pktlabel, strlen(pktlabel));
      //write(outfd, pktbuff, nread);
    }
  }
}
