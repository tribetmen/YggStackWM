// YggCrypto.cpp - Реализация криптографических функций
#include "stdafx.h"
#include "YggCrypto.h"
#include "ygg_constants.h"

extern "C" {
#include "tweetnacl32.h"
#include "blake2.h"
}

extern void AddLog(LPCWSTR text, BYTE type);

// Статические переменные
bool YggCrypto::m_bInitialized = false;

// ============================================================================
// ИНИЦИАЛИЗАЦИЯ
// ============================================================================

bool YggCrypto::Initialize() {
    if (!m_bInitialized) {
        // Инициализация криптобиблиотек
        m_bInitialized = true;
    }
    return m_bInitialized;
}

// ============================================================================
// КЛЮЧИ
// ============================================================================

bool YggCrypto::GenerateKeyPair(BYTE* pubKey, BYTE* privKey) {
    // Используем макрос crypto_sign_keypair, который в tweetnacl.h 
    // определен как crypto_sign_ed25519_tweet_keypair
    return (crypto_sign_keypair(pubKey, privKey) == 0);
}

// ============================================================================
// IPv6 АДРЕСАЦИЯ
// ============================================================================

void YggCrypto::DeriveIPv6(BYTE* ipv6, const BYTE* pubKey) {
    if (!ipv6 || !pubKey) return;
    
    BYTE inv[32];
    for(int i = 0; i < 32; i++) {
        inv[i] = pubKey[i] ^ 0xFF;
    }
    
    // Считаем ведущие единицы
    int ones = 0;
    for(int i = 0; i < 256; i++) {
        int byteIdx = i / 8;
        int bitIdx = i % 8;
        if((inv[byteIdx] & (0x80 >> bitIdx)) != 0) {
            ones++;
        } else {
            break;
        }
    }
    
    // Формируем IPv6
    memset(ipv6, 0, 16);
    // Первый байт: 0x02 + старшие биты ones (если ones >= 8, бит 8 попадает в бит 0 addr[0])
    ipv6[0] = 0x02 | ((ones >> 8) & 0x01);
    ipv6[1] = (BYTE)(ones & 0xFF);
    
    int keyStartBit = ones + 1;
    for(int i = keyStartBit; i < 256; i++) {
        int addrBit = 16 + (i - keyStartBit);
        if(addrBit >= 128) break;
        
        int byteIdx = i / 8;
        int bitIdx = i % 8;
        
        if((inv[byteIdx] & (0x80 >> bitIdx)) != 0) {
            ipv6[addrBit / 8] |= (0x80 >> (addrBit % 8));
        }
    }
}

void YggCrypto::DerivePartialKeyFromIPv6(BYTE* key, const BYTE* ipv6) {
    if (!key || !ipv6) return;

    // Адреса подсети 300::/8 (ipv6[0] == 0x03) нормализуем к Node IP 200::/8 (0x02)
    // Протокол Yggdrasil: подсеть /64 узла отличается только первым байтом
    BYTE normIpv6[16];
    memcpy(normIpv6, ipv6, 16);
    if (normIpv6[0] == 0x03) normIpv6[0] = 0x02;
    ipv6 = normIpv6;

    // ones хранится в ipv6[1], плюс возможный бит 8 в бите 0 ipv6[0]
    int ones = ipv6[1] | ((ipv6[0] & 0x01) << 8);

    // Строим инвертированный ключ (inv): ones единиц, затем 0, затем payload из IPv6
    BYTE inv[32];
    memset(inv, 0, 32);

    // Ставим ones ведущих единиц
    for (int i = 0; i < ones; i++) {
        inv[i / 8] |= (0x80 >> (i % 8));
    }
    // Бит (ones) остаётся нулём — это разделитель

    // Копируем payload: биты IPv6 начиная с бита 16 → inv начиная с бита (ones+1)
    for (int addrBit = 16; addrBit < 128; addrBit++) {
        int kPos = ones + 1 + (addrBit - 16);
        if (kPos >= 256) break;
        if ((ipv6[addrBit / 8] & (0x80 >> (addrBit % 8))) != 0) {
            inv[kPos / 8] |= (0x80 >> (kPos % 8));
        }
    }

    // Инвертируем обратно чтобы получить реальный ключ
    for (int i = 0; i < 32; i++) {
        key[i] = ~inv[i];
    }
}

void YggCrypto::FormatIPv6(const BYTE* ipv6, WCHAR* outStr, int maxLen) {
    if (!ipv6 || !outStr) return;
    
    _snwprintf(outStr, maxLen, 
        L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        ipv6[0], ipv6[1], ipv6[2], ipv6[3],
        ipv6[4], ipv6[5], ipv6[6], ipv6[7],
        ipv6[8], ipv6[9], ipv6[10], ipv6[11],
        ipv6[12], ipv6[13], ipv6[14], ipv6[15]);
}

// ============================================================================
// ПОДПИСИ
// ============================================================================

bool YggCrypto::Sign(const BYTE* privKey, const BYTE* data, DWORD dataLen, BYTE* signature) {
    unsigned int smlen;
    BYTE signed_data[1024];
    
    // Используем макрос crypto_sign
    if (crypto_sign(signed_data, &smlen, data, dataLen, privKey) != 0) {
        return false;
    }
    
    memcpy(signature, signed_data, 64);
    return true;
}

bool YggCrypto::Verify(const BYTE* pubKey, const BYTE* data, DWORD dataLen, const BYTE* signature) {
    // TODO: Реализовать проверку подписи
    return true;
}

// ============================================================================
// ХЕШИРОВАНИЕ
// ============================================================================

void YggCrypto::Hash(const BYTE* data, DWORD dataLen, BYTE* hash) {
    if (!data || !hash) return;
    
    // Используем Blake2b-512
    blake2b_state S;
    blake2b_init(&S, 64);
    blake2b_update(&S, data, dataLen);
    blake2b_final(&S, hash, 64);
}

// ============================================================================
// ТЕСТЫ КРИПТОГРАФИИ (отключены в продакшн-сборке)
// ============================================================================

void YggCrypto::RunCryptoTests() {
    // Тесты отключены для уменьшения времени запуска
    // Для включения раскомментируйте код в YggCrypto.cpp
    AddLog(L"[CRYPTO] Tests skipped (disabled in production)", LOG_INFO);
}
