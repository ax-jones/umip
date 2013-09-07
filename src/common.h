
#ifndef _UMIP_COMMON_H_
#define _UMIP_COMMON_H_

#define HTONS(x) (((0xff & x) << 8) | (x >> 8))
#define NTOHS(x) (((0xff & x) << 8) | (x >> 8))
#define HTONL(x) (HTONS(x >> 16) | (HTONS((x & 0xffff)) << 16))
#define NTOHL(x) (NTOHS(x >> 16) | (NTOHS((x & 0xffff)) << 16))

void _memcpy(uint8_t *, const uint8_t *, uint16_t);
uint8_t _memcmp(uint8_t *, uint8_t *, uint16_t);
void _memset(uint8_t *, uint8_t, uint16_t);
uint16_t _strlen(const char *);

#define dout(...) fprintf(stderr, __VA_ARGS__)

#endif // _UMIP_COMMON_H_
