#ifndef BLAKE2_IMPL_H
#define BLAKE2_IMPL_H

#include <string.h>

// Определяем базовые типы
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
  #if defined(_MSC_VER)
    #define inline __inline
  #endif
#endif

static inline uint32_t load32(const void *src) {
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
}

static inline uint64_t load64(const void *src) {
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
}

static inline void store32(void *dst, uint32_t w) {
    memcpy(dst, &w, sizeof w);
}

static inline void store64(void *dst, uint64_t w) {
    memcpy(dst, &w, sizeof w);
}

static inline uint64_t load48(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    uint64_t w = 0;
    w |= (uint64_t)p[0] <<  0;
    w |= (uint64_t)p[1] <<  8;
    w |= (uint64_t)p[2] << 16;
    w |= (uint64_t)p[3] << 24;
    w |= (uint64_t)p[4] << 32;
    w |= (uint64_t)p[5] << 40;
    return w;
}

static inline void store48(void *dst, uint64_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w >>  0);
    p[1] = (uint8_t)(w >>  8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
    p[4] = (uint8_t)(w >> 32);
    p[5] = (uint8_t)(w >> 40);
}

static inline uint32_t rotr32(const uint32_t w, const unsigned c) {
    return (w >> c) | (w << (32 - c));
}

static inline uint64_t rotr64(const uint64_t w, const unsigned c) {
    return (w >> c) | (w << (64 - c));
}

static inline void secure_zero_memory(void *v, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) *p++ = 0;
}

#endif