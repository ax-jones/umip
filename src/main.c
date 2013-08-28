
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include "utap.h"

void usage(const char *appName) { fprintf(stderr, "Usage: %s <if name>\n", appName); };

int main(int argc, char **argv)
{
  if(argc < 2) {
    usage(argv[0]);
    exit(-1);
  }

  char ifname[IFNAMSIZ], pktbuff[TAP_BUFFER_SIZE];

  strncpy(ifname, "\0", IFNAMSIZ);

  int tapfd = umip_open_tap(ifname), nread;

  if(tapfd < 0) {
    exit(-1);
  }

  printf("Interface %s opened.\n", ifname);

  while(1) {
    nread = read(tapfd, pktbuff, TAP_BUFFER_SIZE);
    if(nread < 0) {
      perror("Reading from interface");
      close(tapfd);
      exit(-1);
    }
    printf("Pkt %i read.\n", nread);
  }
}
