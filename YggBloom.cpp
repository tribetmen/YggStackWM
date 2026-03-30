// YggBloom.cpp - Реализация Bloom фильтров
#include "stdafx.h"
#include "YggBloom.h"
#include "MurmurHash3.h"

// ============================================================================
// КОНСТАНТЫ BLOOM ФИЛЬТРА
// ============================================================================

#define BLOOM_M_BITS        8192    // Размер фильтра в битах
#define BLOOM_K_HASHES      8       // Количество хеш-функций

// ============================================================================
// ГЕНЕРАЦИЯ ФИЛЬТРА
// ============================================================================

void YggBloom::Generate(const BYTE* pubKey, vector<BYTE>& output) {
    // ---------------------------------------------------------
    // ШАГ 1: V2 Key Transformation
    // ---------------------------------------------------------
    BYTE inv[32];
    for (int i = 0; i < 32; i++) {
        inv[i] = pubKey[i] ^ 0xFF;
    }
    
    int ones = 0;
    for (int i = 0; i < 256; i++) {
        if ((inv[i / 8] & (0x80 >> (i % 8))) != 0) {
            ones++;
        } else {
            break;
        }
    }
    
    BYTE subnet[8] = {0};
    subnet[0] = 0x03;
    subnet[1] = (BYTE)ones;
    
    int keyStartBit = ones + 1;
    for (int i = keyStartBit; i < 256; i++) {
        int subnetBit = 16 + (i - keyStartBit);
        if (subnetBit >= 64) break;
        
        if ((inv[i / 8] & (0x80 >> (i % 8))) != 0) {
            subnet[subnetBit / 8] |= (0x80 >> (subnetBit % 8));
        }
    }
    
    BYTE addr[16] = {0};
    memcpy(addr, subnet, 8);
    
    // Используем буфер, выровненный по границе 8 байт, 
    // чтобы ARM-процессор не упал (Data Abort) внутри MurmurHash3_x64_128
    unsigned long long keyAlignedBuf[5] = {0};
    BYTE* keyOut = (BYTE*)keyAlignedBuf;
    
    for (int i = 0; i < ones; i++) {
        keyOut[i / 8] |= (0x80 >> (i % 8));
    }
    
    int keyOffset = ones + 1;
    int addrOffset = 16;
    
    for (int idx = addrOffset; idx < 128; idx++) {
        if ((addr[idx / 8] & (0x80 >> (idx % 8))) != 0) {
            int keyIdx = keyOffset + (idx - addrOffset);
            if (keyIdx >= 256) break;
            keyOut[keyIdx / 8] |= (0x80 >> (keyIdx % 8));
        }
    }
    
    for (int i = 0; i < 32; i++) {
        keyOut[i] = (~keyOut[i]) & 0xFF;
    }

    // ---------------------------------------------------------
    // ШАГ 2: Базовые хэши (Murmur3)
    // ---------------------------------------------------------
    unsigned long long h[4] = {0};
    
    // MurmurHash3 возвращает 128 бит (2 блока по 64 бита)
    unsigned long long outHashBuf[2] = {0};
    
    // Хэш 1: keyOut -> h1, h2
    MurmurHash3_x64_128(keyOut, 32, 0, outHashBuf);
    h[0] = outHashBuf[0];
    h[1] = outHashBuf[1];
    
    // Хэш 2: keyOut || [1] -> h3, h4
    unsigned long long keyOneAlignedBuf[5] = {0};
    BYTE* keyWithOne = (BYTE*)keyOneAlignedBuf;
    memcpy(keyWithOne, keyOut, 32);
    keyWithOne[32] = 1;
    
    MurmurHash3_x64_128(keyWithOne, 33, 0, outHashBuf);
    h[2] = outHashBuf[0];
    h[3] = outHashBuf[1];

    // ---------------------------------------------------------
    // ШАГ 3: Заполнение битов Bloom Фильтра
    // ---------------------------------------------------------
    unsigned long long filter[128] = {0}; // 128 блоков по 64 бита
    
    for (int i = 0; i < BLOOM_K_HASHES; i++) {
        int additiveIndex = i % 2;
        int inner = (i + (i % 2)) % 4;
        int multiplicativeIndex = 2 + (inner / 2);
        
        unsigned long long base = h[additiveIndex];
        unsigned long long mult = h[multiplicativeIndex];
        unsigned long long ii = (unsigned long long)i;
        
        unsigned long long product = ii * mult;
        unsigned long long sum = base + product;
        unsigned long long result = sum % BLOOM_M_BITS;
        
        int bitPos = (int)result;
        int longIndex = bitPos / 64;
        int bitOffset = bitPos % 64;
        
        filter[longIndex] |= (1ULL << bitOffset);
    }

    // ---------------------------------------------------------
    // ШАГ 4: Сериализация Yggdrasil Bloom формата
    // ---------------------------------------------------------
    BYTE flags0[16] = {0};
    BYTE flags1[16] = {0};
    std::vector<unsigned long long> keep;
    
    for (int i = 0; i < 128; i++) {
        unsigned long long val = filter[i];
        if (val == 0) {
            // Блок все нули
            flags0[i / 8] |= (0x80 >> (i % 8));
        } else if (val == 0xFFFFFFFFFFFFFFFFULL) {
            // Блок все единицы
            flags1[i / 8] |= (0x80 >> (i % 8));
        } else {
            // Смешанный блок - сохраняем
            keep.push_back(val);
        }
    }
    
    output.clear();
    
    // Сначала flags0 (16 байт)
    output.insert(output.end(), flags0, flags0 + 16);
    
    // Затем flags1 (16 байт)
    output.insert(output.end(), flags1, flags1 + 16);
    
    // Оставшиеся блоки пишем в Big-Endian (как требует протокол)
    for (size_t i = 0; i < keep.size(); i++) {
        unsigned long long val = keep[i];
        for (int b = 7; b >= 0; b--) {
            output.push_back((BYTE)((val >> (b * 8)) & 0xFF));
        }
    }
}

// ============================================================================
// ЖАДНЫЙ ФИЛЬТР
// ============================================================================

void YggBloom::GenerateGreedy(vector<BYTE>& output) {
    // Все биты установлены
    BYTE greedy[32];
    memset(greedy, 0xFF, 16);
    memset(greedy + 16, 0, 16);
    
    output.clear();
    output.insert(output.end(), greedy, greedy + 32);
}

// ============================================================================
// ПАРСИНГ ФИЛЬТРА
// ============================================================================

bool YggBloom::Parse(const vector<BYTE>& bloom, vector<int>& bits) {
    // TODO: Реализовать парсинг Bloom фильтра
    return false;
}
