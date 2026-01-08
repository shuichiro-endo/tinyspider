/*
 * Title:  aes.h
 * Author: Shuichiro Endo
 */

/*
 * Reference:
 * https://github.com/kokke/tiny-AES-c
 */

#pragma once

#ifndef AES_H_
#define AES_H_

#include "stdfunc.h"

#define AES_BLOCK_LEN 16
#define AES_KEY_LEN 32
#define AES_KEY_EXP_SIZE 240
#define Nb 4
#define Nk 8
#define Nr 14

typedef struct aes_key
{
    char *aes_key_hex_string;
    int32_t aes_key_hex_string_size;
    char *aes_iv_hex_string;
    int32_t aes_iv_hex_string_size;
    unsigned char *key;
    unsigned char *iv;
    unsigned char *round_key;
} aes_key;

typedef unsigned char state_t[4][4];

int init_aes(struct aes_key **a_key, char *key, char *iv);
void key_expansion(unsigned char *round_key, const unsigned char *key);
void aes_init(unsigned char *round_key, const unsigned char *key);
unsigned char get_sbox_value(uint8_t num);
void add_round_key(uint8_t round, state_t *state, const unsigned char *round_key);
void sub_bytes(state_t *state);
void shift_rows(state_t* state);
unsigned char xtime(unsigned char x);
void mix_columns(state_t *state);
unsigned char multiply(unsigned char x, unsigned char y);
unsigned char get_sbox_invert(uint8_t num);
void inv_mix_columns(state_t *state);
void inv_sub_bytes(state_t *state);
void inv_shift_rows(state_t *state);
void cipher(state_t *state, const unsigned char *round_key);
void inv_cipher(state_t *state, const unsigned char *round_key);
void xor_with_iv(unsigned char *buf, const unsigned char *iv);
int32_t add_padding(unsigned char *data, int32_t data_size);
int32_t delete_padding(unsigned char *data, int32_t data_size);
int32_t aes_encrypt(struct aes_key *a_key, char *data, int32_t data_size, int32_t buffer_size);
int32_t aes_decrypt(struct aes_key *a_key, char *data, int32_t data_size, int32_t buffer_size);
void free_aes_key(struct aes_key *a_key);

#endif /* AES_H_ */

