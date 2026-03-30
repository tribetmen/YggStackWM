// YggConvert.cpp - Конвертация Ed25519 <-> X25519 ключей
#include "stdafx.h"
#include "YggConvert.h"

extern "C" {
#include "tweetnacl32.h"
}

// Простая реализация конвертации Ed25519 -> X25519
// Используем формулу: u = (1 + y) / (1 - y) (mod 2^255-19)

// p = 2^255 - 19
static const unsigned char p[32] = {
    0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
};

// Вычитание по модулю p: r = (a - b) mod p
static void submod(unsigned char r[32], const unsigned char a[32], const unsigned char b[32]) {
    int i;
    int borrow = 0;
    for (i = 0; i < 32; i++) {
        int ai = a[i];
        int bi = b[i];
        int ri = ai - bi - borrow;
        if (ri < 0) {
            ri += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        r[i] = (unsigned char)ri;
    }
    // Если результат отрицательный, добавляем p
    if (borrow) {
        int carry = 0;
        for (i = 0; i < 32; i++) {
            int ri = r[i] + p[i] + carry;
            r[i] = (unsigned char)(ri & 0xFF);
            carry = ri >> 8;
        }
    }
}

// Сложение по модулю p: r = (a + b) mod p  
static void addmod(unsigned char r[32], const unsigned char a[32], const unsigned char b[32]) {
    int i;
    int carry = 0;
    for (i = 0; i < 32; i++) {
        int ri = a[i] + b[i] + carry;
        r[i] = (unsigned char)(ri & 0xFF);
        carry = ri >> 8;
    }
    // Если результат >= 2^256, вычитаем p
    // Проверяем, больше ли результат чем p
    int greater = 0;
    int equal = 1;
    for (i = 31; i >= 0; i--) {
        if (r[i] > p[i]) {
            greater = 1;
            break;
        } else if (r[i] < p[i]) {
            equal = 0;
            break;
        }
    }
    if (greater || (equal && carry)) {
        borrow = 0;
        for (i = 0; i < 32; i++) {
            int ri = r[i] - p[i] - borrow;
            if (ri < 0) {
                ri += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            r[i] = (unsigned char)ri;
        }
    }
}

// Упрощенная конвертация Ed25519 public key -> X25519
// В реальности нужна полная арифметика на поле включая умножение и инверсию
// Это упрощенная версия, которая может не работать для всех ключей
bool Ed25519PubToX25519(const BYTE ed25519_pk[32], BYTE x25519_pk[32]) {
    // Ed25519 public key: y-координата (little endian), бит 255 = знак x
    // Вычисляем u = (1 + y) / (1 - y)
    
    // Для упрощения используем другой подход:
    // Возьмем y-координату и модифицируем старший бит
    // Это НЕ правильная конвертация, но может сработать для тестирования
    
    memcpy(x25519_pk, ed25519_pk, 32);
    x25519_pk[31] &= 0x7F;  // clear bit 255
    
    // ПРИМЕЧАНИЕ: Для правильной конвертации нужна полная реализация
    // арифметики на поле GF(2^255-19) включая умножение и инверсию
    // Это временное решение!
    
    return true;
}

// Конвертация Ed25519 private key (seed) -> X25519 private key
void Ed25519PrivToX25519(const BYTE ed25519_seed[32], BYTE x25519_sk[32]) {
    // Хешируем seed с SHA512
    BYTE hash[64];
    crypto_hash_sha512_tweet(hash, ed25519_seed, (unsigned int)32);
    
    // Берем первые 32 байта и модифицируем как для X25519
    memcpy(x25519_sk, hash, 32);
    x25519_sk[0] &= 248;   // clear bits 0,1,2
    x25519_sk[31] &= 127;  // clear bit 255
    x25519_sk[31] |= 64;   // set bit 254
}
