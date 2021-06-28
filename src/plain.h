#ifndef _PLAIN_H
#define _PLAIN_H

#ifndef __MINGW32__
#include <sys/socket.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include "crypto.h"

int plain_encrypt_all(buffer_t *, cipher_t *, size_t);
int plain_decrypt_all(buffer_t *, cipher_t *, size_t);
int plain_encrypt(buffer_t *, cipher_ctx_t *, size_t);
int plain_decrypt(buffer_t *, cipher_ctx_t *, size_t);

void plain_ctx_init(cipher_t *, cipher_ctx_t *, int);
void plain_ctx_release(cipher_ctx_t *);

cipher_t *plain_init(const char *pass, const char *key, const char *method);

#endif // _PLAIN_H
