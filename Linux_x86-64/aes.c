/*
 * Title:  aes.c
 * Author: Shuichiro Endo
 */

/*
 * Reference:
 * https://github.com/kokke/tiny-AES-c
 */

#include "aes.h"

const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const unsigned char rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

int init_aes(struct aes_key **a_key, char *key, char *iv)
{
    if(key != NULL && iv != NULL)
    {
        *a_key = (struct aes_key *)calloc(1, sizeof(struct aes_key));

        (*a_key)->aes_key_hex_string = strdup(key);
        (*a_key)->aes_key_hex_string_size = strlen(key);
        (*a_key)->aes_iv_hex_string = strdup(iv);
        (*a_key)->aes_iv_hex_string_size = strlen(iv);

        (*a_key)->key = (unsigned char *)calloc(AES_KEY_LEN, sizeof(unsigned char));
        (*a_key)->iv = (unsigned char *)calloc(AES_BLOCK_LEN, sizeof(unsigned char));
        (*a_key)->round_key = (unsigned char *)calloc(AES_KEY_EXP_SIZE, sizeof(unsigned char));

        if((*a_key)->aes_key_hex_string_size == AES_KEY_LEN * 2 && (*a_key)->aes_iv_hex_string_size == AES_BLOCK_LEN * 2)
        {
            hex_string_to_array((*a_key)->aes_key_hex_string, (*a_key)->aes_key_hex_string_size, (*a_key)->key, AES_KEY_LEN);
            hex_string_to_array((*a_key)->aes_iv_hex_string, (*a_key)->aes_iv_hex_string_size, (*a_key)->iv, AES_BLOCK_LEN);
            aes_init((*a_key)->round_key, (*a_key)->key);
        }else
        {
            printf("[-] aes key or iv size error: key(%d):%d iv(%d):%d\n", AES_KEY_LEN * 2, (*a_key)->aes_key_hex_string_size, AES_BLOCK_LEN * 2, (*a_key)->aes_iv_hex_string_size);

            return -1;
        }
    }else
    {
        printf("[-] key or iv is NULL\n");

        return -1;
    }

    return 0;
}

void key_expansion(unsigned char *round_key, const unsigned char *key)
{
    uint8_t i, j, k;
    unsigned char tmp[4];

    for(i = 0; i < Nk; ++i)
    {
        round_key[(i * 4) + 0] = key[(i * 4) + 0];
        round_key[(i * 4) + 1] = key[(i * 4) + 1];
        round_key[(i * 4) + 2] = key[(i * 4) + 2];
        round_key[(i * 4) + 3] = key[(i * 4) + 3];
    }

    for(i = Nk; i< Nb * (Nr + 1); ++i)
    {
        k = (i - 1) * 4;
        tmp[0] = round_key[k + 0];
        tmp[1] = round_key[k + 1];
        tmp[2] = round_key[k + 2];
        tmp[3] = round_key[k + 3];

        if(i % Nk == 0)
        {
            const unsigned char u8_tmp = tmp[0];
            tmp[0] = tmp[1];
            tmp[1] = tmp[2];
            tmp[2] = tmp[3];
            tmp[3] = u8_tmp;

            tmp[0] = get_sbox_value(tmp[0]);
            tmp[1] = get_sbox_value(tmp[1]);
            tmp[2] = get_sbox_value(tmp[2]);
            tmp[3] = get_sbox_value(tmp[3]);

            tmp[0] = tmp[0] ^ rcon[i / Nk];
        }

        if(i % Nk == 4)
        {
            tmp[0] = get_sbox_value(tmp[0]);
            tmp[1] = get_sbox_value(tmp[1]);
            tmp[2] = get_sbox_value(tmp[2]);
            tmp[3] = get_sbox_value(tmp[3]);
        }

        j = i * 4;
        k = (i - Nk) * 4;

        round_key[j + 0] = round_key[k + 0] ^ tmp[0];
        round_key[j + 1] = round_key[k + 1] ^ tmp[1];
        round_key[j + 2] = round_key[k + 2] ^ tmp[2];
        round_key[j + 3] = round_key[k + 3] ^ tmp[3];
    }
}

void aes_init(unsigned char *round_key, const unsigned char *key)
{
    key_expansion(round_key, key);
}

unsigned char get_sbox_value(uint8_t num)
{
    return sbox[num];
}

void add_round_key(uint8_t round, state_t *state, const unsigned char *round_key)
{
    uint8_t i, j;

    for(i = 0; i < 4; ++i)
    {
        for(j = 0; j < 4; ++j)
        {
            (*state)[i][j] ^= round_key[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

void sub_bytes(state_t *state)
{
    uint8_t i, j;

    for(i = 0; i < 4; ++i)
    {
        for(j = 0; j < 4; ++j)
        {
            (*state)[j][i] = get_sbox_value((*state)[j][i]);
        }
    }
}

void shift_rows(state_t* state)
{
    unsigned char tmp;

    tmp            = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = tmp;

    tmp            = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = tmp;

    tmp            = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = tmp;

    tmp            = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = tmp;
}

unsigned char xtime(unsigned char x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

void mix_columns(state_t *state)
{
    uint8_t i;
    unsigned char t1, t2, t3;

    for(i = 0; i < 4; ++i)
    {
        t1 = (*state)[i][0];
        t2 = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];

        t3 = (*state)[i][0] ^ (*state)[i][1];
        t3 = xtime(t3);
        (*state)[i][0] ^= t3 ^ t2;

        t3 = (*state)[i][1] ^ (*state)[i][2];
        t3 = xtime(t3);
        (*state)[i][1] ^= t3 ^ t2;

        t3 = (*state)[i][2] ^ (*state)[i][3];
        t3 = xtime(t3);
        (*state)[i][2] ^= t3 ^ t2;

        t3 = (*state)[i][3] ^ t1;
        t3 = xtime(t3);
        (*state)[i][3] ^= t3 ^ t2;
    }
}

unsigned char multiply(unsigned char x, unsigned char y)
{
    return (((y & 1) * x) ^
    ((y >> 1 & 1) * xtime(x)) ^
    ((y >> 2 & 1) * xtime(xtime(x))) ^
    ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
    ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

unsigned char get_sbox_invert(uint8_t num)
{
    return rsbox[num];
}

void inv_mix_columns(state_t *state)
{
    uint8_t i;
    unsigned char a, b, c, d;

    for(i = 0; i < 4; ++i)
    {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        (*state)[i][1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        (*state)[i][2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        (*state)[i][3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}

void inv_sub_bytes(state_t *state)
{
    uint8_t i, j;

    for(i = 0; i < 4; ++i)
    {
        for(j = 0; j < 4; ++j)
        {
            (*state)[j][i] = get_sbox_invert((*state)[j][i]);
        }
    }
}

void inv_shift_rows(state_t *state)
{
    unsigned char tmp;

    tmp            = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = tmp;

    tmp            = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = tmp;

    tmp            = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = tmp;

    tmp            = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = tmp;
}

void cipher(state_t *state, const unsigned char *round_key)
{
    uint8_t round = 0;

    add_round_key(0, state, round_key);

    for(round = 1; ; ++round)
    {
        sub_bytes(state);
        shift_rows(state);

        if(round == Nr)
        {
            break;
        }

        mix_columns(state);
        add_round_key(round, state, round_key);
    }

    add_round_key(Nr, state, round_key);
}

void inv_cipher(state_t *state, const unsigned char *round_key)
{
    uint8_t round = 0;

    add_round_key(Nr, state, round_key);

    for(round = (Nr - 1); ; --round)
    {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(round, state, round_key);

        if(round == 0)
        {
            break;
        }

        inv_mix_columns(state);
    }
}

void xor_with_iv(unsigned char *buf, const unsigned char *iv)
{
    uint8_t i;

    for(i = 0; i < AES_BLOCK_LEN; ++i)
    {
        buf[i] ^= iv[i];
    }
}

int32_t add_padding(unsigned char *data, int32_t data_size)
{
    int32_t i;
    unsigned char pad[AES_BLOCK_LEN];
    int32_t p;

    for(i = 0; i < AES_BLOCK_LEN; i++)
    {
        pad[i] = AES_BLOCK_LEN - i;
    }

    p = data_size % AES_BLOCK_LEN;
    if(p == 0)
    {
        for(i = 0; i < AES_BLOCK_LEN; i++)
        {
            *(data + data_size + i) = pad[0];
        }

        data_size += AES_BLOCK_LEN;
    }else
    {
        for(i = 0; i < AES_BLOCK_LEN - p; i++)
        {
            *(data+data_size + i) = pad[p];
        }

        data_size += pad[p];
    }

    return data_size;
}

int32_t delete_padding(unsigned char *data, int32_t data_size)
{
    int32_t i;
    unsigned char pad = *(data + data_size - 1);

    if(pad < 1 ||
        pad > 16)
    {
        return 0;
    }else if(pad > data_size)
    {
        return -1;
    }else
    {
        for(i = pad; i > 0; i--)
        {
            if(*(data + data_size - i) != pad)  // check padding
            {
                return -1;
            }
        }
    }

    for(i = pad; i > 0; i--)
    {
        *(data + data_size - i) = 0x0;
    }

    data_size -= pad;

    return data_size;
}

int32_t aes_encrypt(struct aes_key *a_key, char *data, int32_t data_size, int32_t buffer_size)
{
    int32_t i;
    unsigned char *iv_tmp = a_key->iv;

    if(data_size + AES_BLOCK_LEN > buffer_size)
    {
#ifdef _DEBUG
        printf("[-] aes_encrypt buffer size error: %d\n", data_size);
#endif
        return -1;
    }

#ifdef _DEBUG
//        print_bytes(data, data_size);
#endif

    data_size = add_padding((unsigned char *)data, data_size);

    for(i = 0; i < data_size; i += AES_BLOCK_LEN)
    {
        xor_with_iv((unsigned char *)data, iv_tmp);

        cipher((state_t *)data, a_key->round_key);

        iv_tmp = (unsigned char *)data;
        data += AES_BLOCK_LEN;
    }

    return data_size;
}

int32_t aes_decrypt(struct aes_key *a_key, char *data, int32_t data_size, int32_t buffer_size)
{
    int32_t ret;
    int32_t i;
    unsigned char *p;
    unsigned char *iv_tmp;

    if(data_size % AES_BLOCK_LEN)
    {
#ifdef _DEBUG
        printf("[-] aes_decrypt data size error: %d\n", data_size);
#endif
        return -1;
    }

    p = (unsigned char *)data + data_size - AES_BLOCK_LEN;
    iv_tmp = (unsigned char *)data + data_size - AES_BLOCK_LEN * 2;

    for(i = data_size - AES_BLOCK_LEN; i >= 0; i -= AES_BLOCK_LEN)
    {
        inv_cipher((state_t *)p, a_key->round_key);

        if(p == (unsigned char *)data)
        {
            xor_with_iv((unsigned char *)p, a_key->iv);
        }else
        {
            xor_with_iv((unsigned char *)p, iv_tmp);
        }

        p -= AES_BLOCK_LEN;
        iv_tmp -= AES_BLOCK_LEN;
    }

    ret = delete_padding((unsigned char *)data, data_size);
    if(ret < 0)
    {
        return -1;
    }else if(ret != 0)
    {
        data_size = ret;
    }

#ifdef _DEBUG
//        print_bytes(data, data_size);
#endif

    return data_size;
}

void free_aes_key(struct aes_key *a_key)
{
    if(a_key != NULL)
    {
        if(a_key->aes_key_hex_string != NULL)
        {
            free(a_key->aes_key_hex_string);
        }

        if(a_key->aes_iv_hex_string != NULL)
        {
            free(a_key->aes_iv_hex_string);
        }

        if(a_key->key != NULL)
        {
            free(a_key->key);
        }

        if(a_key->iv != NULL)
        {
            free(a_key->iv);
        }

        if(a_key->round_key != NULL)
        {
            free(a_key->round_key);
        }

        free(a_key);
    }
}

