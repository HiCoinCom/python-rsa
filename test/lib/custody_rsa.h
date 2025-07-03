#ifndef RUST_LIB_H
#define RUST_LIB_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

void free_c_char(char *ptr);

const char *private_key_encrypt(const char *priv_str, const char *data);

const char *public_key_decrypt(const char *pub_str, const char *data);

#endif  /* RUST_LIB_H */
