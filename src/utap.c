
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int umip_open_tap(char *ifname)
{
  struct ifreq ifr;
  int fd, err;
  char *tundev = "/dev/net/tun";

  if((fd = open(tundev, O_RDWR)) < 0) {
    perror("tap interface open failed");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

  if((err = ioctl(fd, TUNSETIFF, (void*) &ifr)) < 0) {
    perror("tap interface setiff failed");
    close(fd);
    return err;
  }

  strcpy(ifname, ifr.ifr_name);

  return fd;
}
