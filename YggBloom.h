// YggBloom.h - Bloom фильтры для маршрутизации
#pragma once

#include "YggTypes.h"

// ============================================================================
// КЛАСС BLOOM ФИЛЬТРОВ
// ============================================================================

class YggBloom {
public:
    // Генерация Bloom фильтра из публичного ключа
    static void Generate(const BYTE* pubKey, vector<BYTE>& output);
    
    // Генерация "жадного" фильтра (все биты установлены)
    static void GenerateGreedy(vector<BYTE>& output);
    
    // Парсинг фильтра в массив битов
    static bool Parse(const vector<BYTE>& bloom, vector<int>& bits);
};
