// YggCrypto.h - Криптографические функции
#pragma once

#include "YggTypes.h"

// ============================================================================
// КЛАСС КРИПТОГРАФИИ
// ============================================================================

class YggCrypto {
private:
    static bool m_bInitialized;

public:
    // Инициализация криптобиблиотек
    static bool Initialize();
    
    // Генерация пары ключей Ed25519
    static bool GenerateKeyPair(BYTE* pubKey, BYTE* privKey);
    
    // Получение IPv6 адреса из публичного ключа
    static void DeriveIPv6(BYTE* ipv6, const BYTE* pubKey);
    
    // Получение partial key из IPv6 (для PATH_LOOKUP)
    // Заполняет первые 16 байт на основе IPv6, остальные 0xFF
    static void DerivePartialKeyFromIPv6(BYTE* key, const BYTE* ipv6);
    
    // Форматирование IPv6 в строку
    static void FormatIPv6(const BYTE* ipv6, WCHAR* outStr, int maxLen);
    
    // Подпись данных
    static bool Sign(const BYTE* privKey, const BYTE* data, DWORD dataLen, BYTE* signature);
    
    // Проверка подписи
    static bool Verify(const BYTE* pubKey, const BYTE* data, DWORD dataLen, const BYTE* signature);
    
    // Хеширование (BLAKE2b-512)
    static void Hash(const BYTE* data, DWORD dataLen, BYTE* hash);
    
    // Тесты криптографии (отключены в продакшн)
    static void RunCryptoTests();
};
