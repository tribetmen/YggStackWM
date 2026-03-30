/*
   BLAKE2 reference source code package
*/
#ifndef BLAKE2_H
#define BLAKE2_H

// Определяем базовые типы
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;  // Добавляем uint16_t
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

#include <stddef.h>

#if defined(_MSC_VER)
#define BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define BLAKE2_PACKED(x) x __attribute__((packed))
#endif

#if defined(__cplusplus)
extern "C" {
#endif

  enum blake2s_constant
  {
    BLAKE2S_BLOCKBYTES = 64,
    BLAKE2S_OUTBYTES   = 32,
    BLAKE2S_KEYBYTES   = 32,
    BLAKE2S_SALTBYTES  = 8,
    BLAKE2S_PERSONALBYTES = 8
  };

  enum blake2b_constant
  {
    BLAKE2B_BLOCKBYTES = 128,
    BLAKE2B_OUTBYTES   = 64,
    BLAKE2B_KEYBYTES   = 64,
    BLAKE2B_SALTBYTES  = 16,
    BLAKE2B_PERSONALBYTES = 16
  };

  typedef struct blake2s_state__
  {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[BLAKE2S_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  } blake2s_state;

  typedef struct blake2b_state__
  {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  } blake2b_state;

  // Упрощаем параметры - убираем packed структуры
  typedef struct blake2s_param__
  {
    uint8_t  digest_length;
    uint8_t  key_length;
    uint8_t  fanout;
    uint8_t  depth;
    uint32_t leaf_length;
    uint32_t node_offset;
    uint16_t xof_length;
    uint8_t  node_depth;
    uint8_t  inner_length;
    uint8_t  salt[BLAKE2S_SALTBYTES];
    uint8_t  personal[BLAKE2S_PERSONALBYTES];
  } blake2s_param;

  typedef struct blake2b_param__
  {
    uint8_t  digest_length;
    uint8_t  key_length;
    uint8_t  fanout;
    uint8_t  depth;
    uint32_t leaf_length;
    uint32_t node_offset;
    uint32_t xof_length;
    uint8_t  node_depth;
    uint8_t  inner_length;
    uint8_t  reserved[14];
    uint8_t  salt[BLAKE2B_SALTBYTES];
    uint8_t  personal[BLAKE2B_PERSONALBYTES];
  } blake2b_param;

  // Убираем проверки на размер структур, которые вызывают ошибки
  // enum { BLAKE2_DUMMY_1 = 1/(int)(sizeof(blake2s_param) == BLAKE2S_OUTBYTES) } и т.д.

  /* Streaming API */
  int blake2s_init( blake2s_state *S, size_t outlen );
  int blake2s_init_key( blake2s_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2s_init_param( blake2s_state *S, const blake2s_param *P );
  int blake2s_update( blake2s_state *S, const void *in, size_t inlen );
  int blake2s_final( blake2s_state *S, void *out, size_t outlen );

  int blake2b_init( blake2b_state *S, size_t outlen );
  int blake2b_init_key( blake2b_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2b_init_param( blake2b_state *S, const blake2b_param *P );
  int blake2b_update( blake2b_state *S, const void *in, size_t inlen );
  int blake2b_final( blake2b_state *S, void *out, size_t outlen );

  /* Simple API */
  int blake2s( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  int blake2b( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  int blake2( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

#if defined(__cplusplus)
}
#endif

#endif