#ifndef __SHARED_H_
#define __SHARED_H_

#define MAX_STRLEN 32768
#define PREAMBLE_SIZE 66

#define MODE_ENCRYPT 0
#define MODE_DECRYPT 1

int str_crypt(const unsigned char *iv, const unsigned char *pw, unsigned char *str, int mode);

/* vim: set ts=2 sw=2 et ai si: */
#endif
