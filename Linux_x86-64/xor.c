/*
 * Title:  xor.c
 * Author: Shuichiro Endo
 */

#include "xor.h"

int init_xor(struct xor_key **x_key, char *key)
{
    char tmp1 = 0;
    char tmp2 = 0;
    int32_t length = 0;
    int32_t i = 0;

    if(key != NULL)
    {
        *x_key = (struct xor_key *)calloc(1, sizeof(struct xor_key));

        (*x_key)->xor_key_hex_string = strdup(key);
        (*x_key)->xor_key_hex_string_size = strlen(key);

        if((*x_key)->xor_key_hex_string_size % 2 == 0)
        {
            (*x_key)->key_length = (*x_key)->xor_key_hex_string_size / 2;
        }else
        {
            (*x_key)->key_length = (*x_key)->xor_key_hex_string_size / 2 + 1;
        }

        (*x_key)->key = (unsigned char *)calloc((*x_key)->key_length, sizeof(char));

        hex_string_to_array((*x_key)->xor_key_hex_string, (*x_key)->xor_key_hex_string_size, (*x_key)->key, (*x_key)->key_length);
    }else
    {
        printf("[-] key is NULL\n");

        return -1;
    }

    return 0;
}

int32_t xor_encrypt(struct xor_key *x_key, char *data, int32_t data_size, int32_t buffer_size)
{
    int32_t i = 0;

    if(x_key->key_length == 0)
    {
        return 0;
    }else if(x_key->key_length > 0)
    {
        for(i = 0; i < data_size; i++)
        {
            data[i] = data[i] ^ x_key->key[i % x_key->key_length];
        }
    }else
    {
        return -1;
    }

    return data_size;
}

int32_t xor_decrypt(struct xor_key *x_key, char *data, int32_t data_size, int32_t buffer_size)
{
    int32_t i = 0;

    if(x_key->key_length == 0)
    {
        return 0;
    }else if(x_key->key_length > 0)
    {
        for(i = 0; i < data_size; i++)
        {
            data[i] = data[i] ^ x_key->key[i % x_key->key_length];
        }
    }else
    {
        return -1;
    }

    return data_size;
}

void free_xor_key(struct xor_key *x_key)
{
    if(x_key != NULL)
    {
        if(x_key->xor_key_hex_string != NULL)
        {
            free(x_key->xor_key_hex_string);
        }

        if(x_key->key != NULL)
        {
            free(x_key->key);
        }

        free(x_key);
    }
}

