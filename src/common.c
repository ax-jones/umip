
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "common.h"

void _memcpy(uint8_t *dest, const uint8_t *src, uint16_t len)
{
  while(len--) *(dest++) = *(src++);
}
uint8_t _memcmp(uint8_t *src1, uint8_t *src2, uint16_t len)
{
  while(len--) { if(*(src1++) != *(src2++)) return 1; }
  return 0;
}
void _memset(uint8_t *dest, uint8_t b, uint16_t len)
{
  while(len--) *(dest++) = b;
}

uint16_t _strlen(const char *str)
{
  uint16_t l = 0;
  while(*(str++) != '\0') l++;
  return l;
}
