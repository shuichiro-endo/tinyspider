/*
 * Title:  xor.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef XOR_H_
#define XOR_H_

#include "stdfunc.h"

typedef struct xor_key
{
    char *xor_key_hex_string;
    int32_t xor_key_hex_string_size;
    unsigned char *key;
    int32_t key_length;
} xor_key;

int init_xor(struct xor_key **x_key, char *key);
int32_t xor_encrypt(struct xor_key *x_key, char *data, int32_t data_size, int32_t buffer_size);
int32_t xor_decrypt(struct xor_key *x_key, char *data, int32_t data_size, int32_t buffer_size);
void free_xor_key(struct xor_key *x_key);

#endif /* XOR_H_ */

