// IronSession.cpp - Реализация сессии Ironwood
#include "stdafx.h"
#include "IronSession.h"
#include "IronPeer.h"
#include "ygg_constants.h"
#include "YggCrypto.h"
#include "IPv6Packet.h"
#include "YggdrasilCore.h"

extern "C" {
#include "tweetnacl32.h"
}

// For SetThreadPriority
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif

// Конвертация Ed25519 -> X25519 из ed25519_convert.c
extern int crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                                const unsigned char *ed25519_pk);

extern void AddLog(LPCWSTR text, BYTE type);

// ============================================================================
// СТАТИЧЕСКИЕ ПЕРЕМЕННЫЕ ПУЛА КЛЮЧЕЙ
// ============================================================================

PrecomputedKeyPair IronSession::s_keyPool[PRECOMPUTED_KEY_POOL_SIZE];
CRITICAL_SECTION IronSession::s_keyPoolLock;
HANDLE IronSession::s_keyPoolThread = NULL;
volatile BOOL IronSession::s_keyPoolRunning = FALSE;
volatile int IronSession::s_keyPoolAvailable = 0;

// ============================================================================
// РЕАЛИЗАЦИЯ ПУЛА ПРЕДГЕНЕРИРОВАННЫХ КЛЮЧЕЙ
// ============================================================================

void IronSession::InitKeyPool() {
    InitializeCriticalSection(&s_keyPoolLock);
    s_keyPoolRunning = TRUE;
    
    // Генерируем только MIN_KEYS_AT_START при старте (быстро! ~4 сек)
    int initialCount = min(KEYPOOL_MIN_KEYS_AT_START, PRECOMPUTED_KEY_POOL_SIZE);
    AddLog(L"[KEYPOOL] Pre-generating minimum keys...", LOG_INFO);
    DWORD start = GetTickCount();
    
    for (int i = 0; i < initialCount; i++) {
        crypto_box_keypair(s_keyPool[i].pub, s_keyPool[i].priv);
        s_keyPool[i].used = false;
        s_keyPoolAvailable++;
    }
    
    DWORD elapsed = GetTickCount() - start;
    WCHAR debug[256];
    wsprintf(debug, L"[KEYPOOL] %d keys ready in %lums", s_keyPoolAvailable, elapsed);
    AddLog(debug, LOG_SUCCESS);
    
    // Запускаем фоновый поток с IDLE приоритетом (не мешает никому!)
    if (KEYPOOL_IDLE_TARGET > 0) {
        s_keyPoolThread = CreateThread(NULL, 0, KeyPoolBackgroundThreadProc, NULL, 0, NULL);
        if (s_keyPoolThread) {
            SetThreadPriority(s_keyPoolThread, THREAD_PRIORITY_IDLE);
            AddLog(L"[KEYPOOL] Background thread started (IDLE priority)", LOG_INFO);
        }
    } else {
        AddLog(L"[KEYPOOL] Background thread disabled (TARGET=0)", LOG_INFO);
    }
}

DWORD WINAPI IronSession::KeyPoolBackgroundThreadProc(LPVOID lpParam) {
    (void)lpParam;  // Unused
    AddLog(L"[KEYPOOL] Background thread started (IDLE)", LOG_DEBUG);
    
    // Работаем постоянно с большими паузами
    while (s_keyPoolRunning) {
        // Проверяем сколько ключей нужно
        int currentCount = s_keyPoolAvailable;
        
        if (currentCount >= KEYPOOL_IDLE_TARGET) {
            // Достаточно ключей - спим 5 секунд и проверяем снова
            for (int i = 0; i < 50 && s_keyPoolRunning; i++) {
                Sleep(100);  // 5 секунд total
            }
            continue;
        }
        
        // Ищем слот для нового ключа:
        // - used=true означает "выдан, слот свободен для генерации нового"
        // - pub[0]==0 означает "незаполненный слот (никогда не инициализировался)"
        int slot = -1;
        EnterCriticalSection(&s_keyPoolLock);
        for (int j = 0; j < PRECOMPUTED_KEY_POOL_SIZE; j++) {
            if (s_keyPool[j].used || s_keyPool[j].pub[0] == 0) {
                slot = j;
                // Обнуляем чтобы GetPrecomputedKeyPair не выдал этот слот пока генерируем
                memset(s_keyPool[slot].pub, 0, 32);
                memset(s_keyPool[slot].priv, 0, 32);
                s_keyPool[slot].used = true;  // помечаем как "в работе"
                break;
            }
        }
        LeaveCriticalSection(&s_keyPoolLock);

        if (slot < 0) {
            // Все слоты заняты готовыми ключами — спим
            Sleep(1000);
            continue;
        }

        // Генерируем ключ вне критической секции (медленная операция)
        BYTE tempPub[32], tempPriv[32];
        crypto_box_keypair(tempPub, tempPriv);

        // Записываем готовый ключ и помечаем как доступный
        EnterCriticalSection(&s_keyPoolLock);
        memcpy(s_keyPool[slot].pub, tempPub, 32);
        memcpy(s_keyPool[slot].priv, tempPriv, 32);
        s_keyPool[slot].used = false;
        s_keyPoolAvailable++;
        LeaveCriticalSection(&s_keyPoolLock);
        
        WCHAR debug[256];
        wsprintf(debug, L"[KEYPOOL] Idle generated key, now %d/%d", 
                 s_keyPoolAvailable, KEYPOOL_IDLE_TARGET);
        AddLog(debug, LOG_DEBUG);
        
        // Большая пауза между ключами (даем CPU другим потокам)
        // IDLE приоритет + пауза = минимальное влияние на систему
        for (int i = 0; i < 5 && s_keyPoolRunning; i++) {
            Sleep(100);  // 3 секунды между ключами
        }
    }
    
    AddLog(L"[KEYPOOL] Background thread completed", LOG_DEBUG);
    return 0;
}

bool IronSession::GetPrecomputedKeyPair(BYTE* outPub, BYTE* outPriv) {
    if (!outPub || !outPriv) return false;
    
    EnterCriticalSection(&s_keyPoolLock);
    
    if (s_keyPoolAvailable <= 0) { // Обязательная проверка
        LeaveCriticalSection(&s_keyPoolLock);
        return false; 
    }

    for (int i = 0; i < PRECOMPUTED_KEY_POOL_SIZE; i++) {
        if (!s_keyPool[i].used && s_keyPool[i].pub[0] != 0) {
            memcpy(outPub, s_keyPool[i].pub, 32);
            memcpy(outPriv, s_keyPool[i].priv, 32);
            s_keyPool[i].used = true;
            s_keyPoolAvailable--;
            
            LeaveCriticalSection(&s_keyPoolLock);
            return true;
        }
    }
    
    LeaveCriticalSection(&s_keyPoolLock);
    
    // Пул пуст - генерируем on-demand (как раньше)
    AddLog(L"[KEYPOOL] Pool empty, generating on-demand", LOG_WARN);
    return false;  // Вызовущий код должен сгенерировать сам
}

int IronSession::GetKeyPoolAvailableCount() {
    return s_keyPoolAvailable;
}

void IronSession::ShutdownKeyPool() {
    s_keyPoolRunning = FALSE;
    
    // Ждем завершения фонового потока
    for (int i = 0; i < 50 && s_keyPoolThread != NULL; i++) {
        Sleep(100);
    }
    
    if (s_keyPoolThread) {
        CloseHandle(s_keyPoolThread);
        s_keyPoolThread = NULL;
    }
    
    DeleteCriticalSection(&s_keyPoolLock);
}

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

#define MAX_DECRYPTION_ERRORS       3
#define MAX_REASSEMBLY_SIZE         (512 * 1024)  // 512KB
#define REASSEMBLY_TIMEOUT          2000          // 2 seconds
#define KEY_ROTATION_INTERVAL       60000         // 60 seconds minimum between rotations (matches Go: time.Minute)
#define MAX_SEQ_JUMP                32768

#define CORE_TYPE_TRAFFIC           0x01
#define CORE_TYPE_PROTO             0x02

// ============================================================================
// ОБЕРТКИ ДЛЯ TWEETNACL (Padding буферов)
// ============================================================================

// Обертка для шифрования с правильными отступами (padding) для TweetNaCl
static bool BoxEncrypt(const BYTE* plaintext, DWORD plainLen, 
                       const BYTE* nonce, const BYTE* theirPub, const BYTE* myPriv, 
                       std::vector<BYTE>& outCiphertext) {
    // Выделяем буфер под открытый текст: 32 байта нулей + данные
    std::vector<BYTE> padded_m(plainLen + 32, 0);
    memcpy(&padded_m[32], plaintext, plainLen);
    
    // Выделяем буфер под шифротекст такого же размера
    std::vector<BYTE> padded_c(plainLen + 32, 0);
    
    if (crypto_box(&padded_c[0], &padded_m[0], plainLen + 32, nonce, theirPub, myPriv) != 0) {
        return false;
    }
    
    // Полезные данные (MAC + шифротекст) начинаются с 16-го байта
    outCiphertext.assign(padded_c.begin() + 16, padded_c.end());
    return true;
}

// Оптимизированная версия с использованием beforenm (в 10-20 раз быстрее!)
static bool BoxEncryptFast(const BYTE* plaintext, DWORD plainLen,
                           const BYTE* nonce, const BYTE* sharedKey,  // 32 bytes from crypto_box_beforenm
                           std::vector<BYTE>& outCiphertext) {
    // Выделяем буфер под открытый текст: 32 байта нулей + данные
    std::vector<BYTE> padded_m(plainLen + 32, 0);
    memcpy(&padded_m[32], plaintext, plainLen);
    
    // Выделяем буфер под шифротекст такого же размера
    std::vector<BYTE> padded_c(plainLen + 32, 0);
    
    // Используем afternm - намного быстрее, нет scalar multiplication
    if (crypto_box_afternm(&padded_c[0], &padded_m[0], plainLen + 32, nonce, sharedKey) != 0) {
        return false;
    }
    
    // Полезные данные (MAC + шифротекст) начинаются с 16-го байта
    outCiphertext.assign(padded_c.begin() + 16, padded_c.end());
    return true;
}

// Обертка для дешифровки с правильными отступами (padding) для TweetNaCl
static bool BoxDecrypt(const BYTE* ciphertext, DWORD cipherLen, 
                       const BYTE* nonce, const BYTE* theirPub, const BYTE* myPriv, 
                       std::vector<BYTE>& outPlaintext) {
    if (cipherLen < 16) return false;
    
    // Выделяем буфер под шифротекст: 16 байт нулей + данные
    std::vector<BYTE> padded_c(cipherLen + 16, 0);
    memcpy(&padded_c[16], ciphertext, cipherLen);
    
    // Выделяем буфер под расшифрованный текст
    std::vector<BYTE> padded_m(cipherLen + 16, 0);
    
    if (crypto_box_open(&padded_m[0], &padded_c[0], cipherLen + 16, nonce, theirPub, myPriv) != 0) {
        return false;
    }
    
    // Полезные расшифрованные данные начинаются с 32-го байта
    outPlaintext.assign(padded_m.begin() + 32, padded_m.end());
    return true;
}

// Оптимизированная версия дешифровки (в 20-30 раз быстрее!)
// Использует заранее вычисленный shared key (crypto_box_open_afternm)
static bool BoxDecryptFast(const BYTE* ciphertext, DWORD cipherLen, 
                           const BYTE* nonce, const BYTE* sharedKey, 
                           std::vector<BYTE>& outPlaintext) {
    if (cipherLen < 16) return false;
    
    // Выделяем буфер под шифротекст: 16 байт нулей + данные
    std::vector<BYTE> padded_c(cipherLen + 16, 0);
    memcpy(&padded_c[16], ciphertext, cipherLen);
    
    // Выделяем буфер под расшифрованный текст
    std::vector<BYTE> padded_m(cipherLen + 16, 0);
    
    // Используем afternm - не делает скалярного умножения!
    if (crypto_box_open_afternm(&padded_m[0], &padded_c[0], cipherLen + 16, nonce, sharedKey) != 0) {
        return false;
    }
    
    // Полезные расшифрованные данные начинаются с 32-го байта
    outPlaintext.assign(padded_m.begin() + 32, padded_m.end());
    return true;
}

// ============================================================================
// КОНСТРУКТОР / ДЕСТРУКТОР
// ============================================================================

IronSession::IronSession(const BYTE* remoteKey, int targetPort, unsigned long long initialKeySeq) {
    memcpy(m_remoteKey, remoteKey, KEY_SIZE);
    
    // Конвертируем Ed25519 в X25519 (упрощенно - копируем)
    memcpy(m_remoteXPub, remoteKey, KEY_SIZE);
    
    // Выводим IPv6 из публичного ключа для поиска сессии
    YggCrypto::DeriveIPv6(m_remoteIPv6, remoteKey);
    
    m_targetPort = targetPort;
    m_sourcePort = (GetTickCount() % 60000) + 1024;
    
    m_remoteKeySeq = 0;
    m_localKeySeq = initialKeySeq;
    
    m_sendNonce = 0;
    m_recvNonce = 0;
    m_nextSendNonce = 0;
    m_nextRecvNonce = 0;
    
    m_localSeq = GetTickCount();
    m_remoteSeq = 0;
    m_remoteAck = 0;
    m_nextExpectedSeq = 0;
    
    m_tcpState = TCP_CLOSED;
    m_synSent = false;
    
    m_bReady = false;
    m_bClosed = false;
    m_inUse = false;
    m_lastRotation = 0;
    m_lastActivity = GetTickCount();
    m_decryptionErrors = 0;
    
    m_reassemblyBufferSize = 0;
    m_oldestBufferedTime = 0;
    m_dupAckCount = 0;
    
    m_refCount = 1;
    
    memset(m_recvShared, 0, KEY_SIZE);
    memset(m_sendShared, 0, KEY_SIZE);
    memset(m_nextSendShared, 0, KEY_SIZE);
    memset(m_nextRecvShared, 0, KEY_SIZE);
    
    memset(m_remoteCurrentPub, 0, KEY_SIZE);
    memset(m_remoteNextPub, 0, KEY_SIZE);
    
    // Callback и очередь приема
    m_dataCallback = NULL;
    m_callbackContext = NULL;
    InitializeCriticalSection(&m_recvQueueLock);
    m_recvEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    
    InitializeCriticalSection(&m_lock);
    
    WCHAR debug[256];
    wsprintf(debug, L"[SESSION] Created for port %d, KeySeq=%llu", targetPort, initialKeySeq);
    AddLog(debug, LOG_DEBUG);
}

IronSession::~IronSession() {
    Cleanup();
    DeleteCriticalSection(&m_lock);
    DeleteCriticalSection(&m_recvQueueLock);
    if (m_recvEvent) CloseHandle(m_recvEvent);
}

// ============================================================================
// ИНИЦИАЛИЗАЦИЯ
// ============================================================================

bool IronSession::Initialize() {
    EnterCriticalSection(&m_lock);
    
    GenerateInitialKeys();
    
    LeaveCriticalSection(&m_lock);
    return true;
}

void IronSession::GenerateInitialKeys() {
    // Используем предгенерированные ключи из пула (быстро!)
    DWORD start = GetTickCount();
    
    WCHAR debug[256];
    
    // recv ключи
    if (!GetPrecomputedKeyPair(m_recvPub, m_recvPriv)) {
        // Fallback - генерируем если пул пуст
        crypto_box_keypair(m_recvPub, m_recvPriv);
        AddLog(L"[SESSION] Pool empty, generated recv keys on-demand", LOG_WARN);
    }
    
    // send ключи
    if (!GetPrecomputedKeyPair(m_sendPub, m_sendPriv)) {
        crypto_box_keypair(m_sendPub, m_sendPriv);
        AddLog(L"[SESSION] Pool empty, generated send keys on-demand", LOG_WARN);
    }
    
    // next ключи
    if (!GetPrecomputedKeyPair(m_nextPub, m_nextPriv)) {
        crypto_box_keypair(m_nextPub, m_nextPriv);
        AddLog(L"[SESSION] Pool empty, generated next keys on-demand", LOG_WARN);
    }
    
    // Verify keys are not zero (paranoid check for pool corruption)
    bool recvZero = true, sendZero = true, nextZero = true;
    for (int i = 0; i < 32; i++) {
        if (m_recvPub[i] != 0) recvZero = false;
        if (m_sendPub[i] != 0) sendZero = false;
        if (m_nextPub[i] != 0) nextZero = false;
    }
    
    if (recvZero) {
        AddLog(L"[SESSION] WARNING: recv keys are zero, regenerating!", LOG_WARN);
        crypto_box_keypair(m_recvPub, m_recvPriv);
    }
    if (sendZero) {
        AddLog(L"[SESSION] WARNING: send keys are zero, regenerating!", LOG_WARN);
        crypto_box_keypair(m_sendPub, m_sendPriv);
    }
    if (nextZero) {
        AddLog(L"[SESSION] WARNING: next keys are zero, regenerating!", LOG_WARN);
        crypto_box_keypair(m_nextPub, m_nextPriv);
    }
    
    DWORD keygenTime = GetTickCount() - start;
    int poolRemaining = GetKeyPoolAvailableCount();
    
    wsprintf(debug, L"[SESSION] Keys ready in %lums (pool: %d remaining), KeySeq=%llu, sendPub[0..3]=%02x%02x%02x%02x", 
             keygenTime, poolRemaining, m_localKeySeq, m_sendPub[0], m_sendPub[1], m_sendPub[2], m_sendPub[3]);
    AddLog(debug, LOG_DEBUG);
}

// ============================================================================
// УПРАВЛЕНИЕ СЕССИЕЙ
// ============================================================================

void IronSession::Close() {
    EnterCriticalSection(&m_lock);
    m_bClosed = true;
    m_bReady = false;
    LeaveCriticalSection(&m_lock);
}

void IronSession::Cleanup() {
    EnterCriticalSection(&m_lock);
    m_reassemblyBuffer.clear();
    m_reassemblyBufferSize = 0;
    m_earlyRecvData.clear();
    m_pendingData.clear();
    m_tcpState = TCP_CLOSED;
    m_dupAckCount = 0;
    LeaveCriticalSection(&m_lock);
    
    // Очищаем очередь приема
    EnterCriticalSection(&m_recvQueueLock);
    m_recvQueue.clear();
    LeaveCriticalSection(&m_recvQueueLock);
    
    if (m_recvEvent) {
        SetEvent(m_recvEvent);  // Разблокируем ожидающих
    }
    
    AddLog(L"[SESSION] Cleanup completed", LOG_DEBUG);
}

// ============================================================================
// СБРОС TCP ДЛЯ ПОВТОРНОГО ИСПОЛЬЗОВАНИЯ IRONWOOD-СЕССИИ
// ============================================================================

// Атомарно: если сессия в CLOSED/FIN_WAIT — сбрасывает и возвращает true (поток-инициатор SYN).
// Если уже SYN_SENT/ESTABLISHED — возвращает false (другой поток занимается).
bool IronSession::TryClaimSynInitiator() {
    EnterCriticalSection(&m_lock);
    TcpState st = m_tcpState;
    // Также захватываем если SYN_SENT но m_synSent=false (не должно быть, но на всякий случай)
    bool claimed = (st == TCP_CLOSED || st == TCP_FIN_WAIT);
    if (claimed) {
        // Сбрасываем состояние; m_synSent и TCP_SYN_SENT выставит SendSYN
        m_tcpState = TCP_CLOSED;
        m_synSent = false;
        m_bClosed = false;
        m_localSeq = GetTickCount();
        m_remoteSeq = 0;
        m_remoteAck = 0;
        m_nextExpectedSeq = 0;
        m_sourcePort = (GetTickCount() % 60000) + 1024;
        m_reassemblyBuffer.clear();
        m_reassemblyBufferSize = 0;
        m_earlyRecvData.clear();
        m_oldestBufferedTime = 0;
        m_dupAckCount = 0;
        m_pendingData.clear();
        // Сразу помечаем SYN_SENT чтобы конкурентные потоки не прошли сюда
        m_tcpState = TCP_SYN_SENT;
        m_synSent = true;
    }
    LeaveCriticalSection(&m_lock);

    if (claimed) {
        EnterCriticalSection(&m_recvQueueLock);
        m_recvQueue.clear();
        LeaveCriticalSection(&m_recvQueueLock);
        AddLog(L"[SESSION] TCP state claimed for reuse", LOG_DEBUG);
    }
    return claimed;
}

void IronSession::ResetTcpState() {
    // Сбрасываем только TCP-стек — Ironwood-криптография остаётся нетронутой
    EnterCriticalSection(&m_lock);
    m_tcpState = TCP_CLOSED;
    m_synSent = false;
    m_bClosed = false;
    // m_inUse намеренно НЕ сбрасывается здесь — управляется только через TryAcquireUse/ReleaseUse
    m_localSeq = GetTickCount();   // новый ISN
    m_remoteSeq = 0;
    m_remoteAck = 0;
    m_nextExpectedSeq = 0;
    m_sourcePort = (GetTickCount() % 60000) + 1024;  // новый source port
    m_reassemblyBuffer.clear();
    m_reassemblyBufferSize = 0;
    m_earlyRecvData.clear();
    m_oldestBufferedTime = 0;
    m_dupAckCount = 0;
    m_pendingData.clear();
    LeaveCriticalSection(&m_lock);

    EnterCriticalSection(&m_recvQueueLock);
    m_recvQueue.clear();
    LeaveCriticalSection(&m_recvQueueLock);

    AddLog(L"[SESSION] TCP state reset for reuse", LOG_DEBUG);
}

// ============================================================================
// РОТАЦИЯ КЛЮЧЕЙ
// ============================================================================

void IronSession::RotateKeys() {
    // Сдвигаем ключи: send -> recv, next -> send, генерируем новый next
    memcpy(m_recvPub, m_sendPub, KEY_SIZE);
    memcpy(m_recvPriv, m_sendPriv, KEY_SIZE);
    memcpy(m_sendPub, m_nextPub, KEY_SIZE);
    memcpy(m_sendPriv, m_nextPriv, KEY_SIZE);
    
    // Генерируем новую пару next
    crypto_box_keypair(m_nextPub, m_nextPriv);
    
    m_localKeySeq++;
    
    WCHAR debug[256];
    wsprintf(debug, L"[SESSION] Keys rotated, new KeySeq=%llu", m_localKeySeq);
    AddLog(debug, LOG_INFO);
}

void IronSession::FixShared(DWORD recvNonceVal, DWORD sendNonceVal) {
    // Вычисляем shared secrets через X25519
    crypto_box_beforenm(m_recvShared, m_remoteCurrentPub, m_recvPriv);
    crypto_box_beforenm(m_sendShared, m_remoteCurrentPub, m_sendPriv);
    crypto_box_beforenm(m_nextSendShared, m_remoteNextPub, m_sendPriv);
    crypto_box_beforenm(m_nextRecvShared, m_remoteNextPub, m_recvPriv);
    
    m_recvNonce = recvNonceVal;
    m_sendNonce = sendNonceVal;
    m_nextSendNonce = 0;
    m_nextRecvNonce = 0;
    
    AddLog(L"[SESSION] Shared secrets computed", LOG_DEBUG);
}

void IronSession::PerformKeyRotation(const BYTE* theirNextPub, DWORD nonce) {
    m_lastRotation = GetTickCount();
    
    // Сдвигаем ключи удаленной стороны
    memcpy(m_remoteCurrentPub, m_remoteNextPub, KEY_SIZE);
    memcpy(m_remoteNextPub, theirNextPub, KEY_SIZE);
    m_remoteKeySeq++;
    
    // Ротируем наши ключи
    RotateKeys();
    FixShared(0, 0);
    
    WCHAR debug[256];
    wsprintf(debug, L"[SESSION] Full rotation completed, KeySeq=%llu", m_localKeySeq);
    AddLog(debug, LOG_INFO);
}

// ============================================================================
// ОТПРАВКА SESSION_INIT
// ============================================================================

bool IronSession::SendSessionInit(IronPeer* peer, const vector<BYTE>& path) {
    if (!peer) {
        AddLog(L"[SESSION] SendSessionInit: peer is NULL!", LOG_ERROR);
        return false;
    }

    EnterCriticalSection(&m_lock);

    if (m_bClosed) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    DWORD initStart = GetTickCount();

    // Формируем эфемерную пару ключей для handshake (из пула!)
    BYTE ephPriv[32], ephPub[32];
    DWORD kpStart = GetTickCount();
    
    if (!GetPrecomputedKeyPair(ephPub, ephPriv)) {
        // Fallback - генерируем если пул пуст
        crypto_box_keypair(ephPub, ephPriv);
        AddLog(L"[SESSION_INIT] Pool empty, generated ephemeral keys on-demand", LOG_WARN);
    }
    
    DWORD kpTime = GetTickCount() - kpStart;
    
    WCHAR debug[256];
    wsprintf(debug, L"[SESSION_INIT] Got ephemeral keys in %lums (pool: %d remaining)", 
             kpTime, GetKeyPoolAvailableCount());
    AddLog(debug, LOG_DEBUG);
    
    // Проверяем что ключи сессии инициализированы
    bool sendKeyZero = true, nextKeyZero = true;
    for (int i = 0; i < 32; i++) {
        if (m_sendPub[i] != 0) { sendKeyZero = false; break; }
    }
    for (int i = 0; i < 32; i++) {
        if (m_nextPub[i] != 0) { nextKeyZero = false; break; }
    }
    if (sendKeyZero || nextKeyZero) {
        AddLog(L"[SESSION_INIT] WARNING: Session keys not initialized, trying to get from pool...", LOG_WARN);
        
        // Try to get from pool or generate on-demand
        if (sendKeyZero) {
            if (!GetPrecomputedKeyPair(m_sendPub, m_sendPriv)) {
                crypto_box_keypair(m_sendPub, m_sendPriv);
                AddLog(L"[SESSION_INIT] Generated send keys on-demand", LOG_WARN);
            } else {
                AddLog(L"[SESSION_INIT] Got send keys from pool", LOG_WARN);
            }
        }
        if (nextKeyZero) {
            if (!GetPrecomputedKeyPair(m_nextPub, m_nextPriv)) {
                crypto_box_keypair(m_nextPub, m_nextPriv);
                AddLog(L"[SESSION_INIT] Generated next keys on-demand", LOG_WARN);
            } else {
                AddLog(L"[SESSION_INIT] Got next keys from pool", LOG_WARN);
            }
        }
        
        // Re-check
        sendKeyZero = true; nextKeyZero = true;
        for (int i = 0; i < 32; i++) {
            if (m_sendPub[i] != 0) { sendKeyZero = false; break; }
        }
        for (int i = 0; i < 32; i++) {
            if (m_nextPub[i] != 0) { nextKeyZero = false; break; }
        }
        
        if (sendKeyZero || nextKeyZero) {
            AddLog(L"[SESSION_INIT] ERROR: Session keys still not initialized after fallback!", LOG_ERROR);
            LeaveCriticalSection(&m_lock);
            return false;
        }
    }
    
    wsprintf(debug, L"[SESSION_INIT] Using sendPub[0..3]=%02x%02x%02x%02x, nextPub[0..3]=%02x%02x%02x%02x",
             m_sendPub[0], m_sendPub[1], m_sendPub[2], m_sendPub[3],
             m_nextPub[0], m_nextPub[1], m_nextPub[2], m_nextPub[3]);
    AddLog(debug, LOG_DEBUG);
    
    CYggdrasilCore* core = CYggdrasilCore::GetInstance();
    const BYTE* ourEdPub = core->GetKeys().publicKey;
    
    // Получаем текущее время в формате SYSTEMTIME (WinCE совместимо)
    SYSTEMTIME st;
    GetSystemTime(&st); 

    // 2. Конвертируем в FILETIME (количество 100-наносекундных интервалов с 1601 года)
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);

    // 3. Собираем 64-битное число
    unsigned long long ll = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    
    // 4. Сдвигаем эпоху с Windows (1601) на Unix (1970)
    // Разница составляет 11644473600 секунд. 
    // В 100-наносекундных интервалах это: 11644473600 * 10 000 000
    ll -= 116444736000000000ULL;

    // 5. Конвертируем 100-наносекундные интервалы в СЕКУНДЫ (деление на 10,000,000)
    // Go: time.Now().Unix() — секунды с Unix epoch
    unsigned long long timestamp = ll / 10000000ULL;
    
    // Формируем буфер для подписи (112 байт): ephPub + sendPub + nextPub + keySeq + timestamp
    BYTE toSign[112];
    memcpy(toSign, ephPub, 32);
    memcpy(toSign + 32, m_sendPub, 32);
    memcpy(toSign + 64, m_nextPub, 32);
    
    // localKeySeq (8 байт, big endian)
    toSign[96] = (BYTE)(m_localKeySeq >> 56);
    toSign[97] = (BYTE)(m_localKeySeq >> 48);
    toSign[98] = (BYTE)(m_localKeySeq >> 40);
    toSign[99] = (BYTE)(m_localKeySeq >> 32);
    toSign[100] = (BYTE)(m_localKeySeq >> 24);
    toSign[101] = (BYTE)(m_localKeySeq >> 16);
    toSign[102] = (BYTE)(m_localKeySeq >> 8);
    toSign[103] = (BYTE)(m_localKeySeq);
    
    // timestamp (8 байт, big endian)
    toSign[104] = (BYTE)(timestamp >> 56);
    toSign[105] = (BYTE)(timestamp >> 48);
    toSign[106] = (BYTE)(timestamp >> 40);
    toSign[107] = (BYTE)(timestamp >> 32);
    toSign[108] = (BYTE)(timestamp >> 24);
    toSign[109] = (BYTE)(timestamp >> 16);
    toSign[110] = (BYTE)(timestamp >> 8);
    toSign[111] = (BYTE)(timestamp);
    
    // Подписываем данные нашим приватным Ed25519 ключом
    BYTE signature[64];
    DWORD signStart = GetTickCount();
    YggCrypto::Sign(core->GetKeys().privateKey, toSign, sizeof(toSign), signature);
    DWORD signTime = GetTickCount() - signStart;
    
    wsprintf(debug, L"[SESSION_INIT] Ed25519 sign took %lums", signTime);
    AddLog(debug, LOG_DEBUG);
    
    // Формируем финальный plaintext (144 байт)
    BYTE plaintext[144];
    memcpy(plaintext, signature, 64);              // Подпись (64 байта)
    memcpy(plaintext + 64, m_sendPub, 32);         // sendPub (32 байта)
    memcpy(plaintext + 96, m_nextPub, 32);         // nextPub (32 байта)
    memcpy(plaintext + 128, toSign + 96, 16);      // keySeq + timestamp (16 байт)
    
    // Шифруем через обертку BoxEncrypt (оптимизированная версия с beforenm)
    BYTE nonceBytes[24] = {0};
    
    BYTE remoteX25519[32];
    DWORD convStart = GetTickCount();
    
    wsprintf(debug, L"[SESSION_INIT] Converting remoteKey[0..3]=%02x%02x%02x%02x to X25519", 
             m_remoteKey[0], m_remoteKey[1], m_remoteKey[2], m_remoteKey[3]);
    AddLog(debug, LOG_DEBUG);
    
    if (crypto_sign_ed25519_pk_to_curve25519(remoteX25519, m_remoteKey) != 0) {
        AddLog(L"[SESSION_INIT] Ed25519->X25519 conversion failed!", LOG_ERROR);
        LeaveCriticalSection(&m_lock);
        return false;
    }
    DWORD convTime = GetTickCount() - convStart;
    
    // Используем обычное шифрование (beforenm тоже медленный на ARM!)
    vector<BYTE> ciphertext;
    DWORD encStart = GetTickCount();
    if (!BoxEncrypt(plaintext, sizeof(plaintext), nonceBytes, remoteX25519, ephPriv, ciphertext)) {
        LeaveCriticalSection(&m_lock);
        AddLog(L"[SESSION] Failed to encrypt INIT", LOG_ERROR);
        return false;
    }
    DWORD encTime = GetTickCount() - encStart;
    
    DWORD totalTime = GetTickCount() - initStart;
    wsprintf(debug, L"[SESSION_INIT] Conversion: %lums, Encryption: %lums, TOTAL: %lums", 
             convTime, encTime, totalTime);
    AddLog(debug, LOG_INFO);
    
    // Формируем пакет SESSION_INIT
    vector<BYTE> packet;
    packet.push_back(WIRE_TRAFFIC);
    packet.insert(packet.end(), path.begin(), path.end());
    packet.push_back(0); // switch port
    packet.insert(packet.end(), ourEdPub, ourEdPub + 32);
    packet.insert(packet.end(), m_remoteKey, m_remoteKey + 32);
    
    // Номер протокола Session: 0x40 (64)
    packet.push_back(0x40);
    
    // SESSION_INIT type
    packet.push_back(SESSION_INIT);
    packet.insert(packet.end(), ephPub, ephPub + 32);
    packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
    
    // --- Добавляем фрейминг TCP (Uvarint длина пакета) ---
    vector<BYTE> framedPacket;
    DWORD packetLen = packet.size();
    
    // Пишем длину в формате Uvarint
    while (packetLen >= 0x80) {
        framedPacket.push_back((BYTE)((packetLen & 0x7F) | 0x80));
        packetLen >>= 7;
    }
    framedPacket.push_back((BYTE)packetLen);
    
    // Копируем сам пакет после длины
    framedPacket.insert(framedPacket.end(), packet.begin(), packet.end());
    
    LeaveCriticalSection(&m_lock);
    
    // Логируем отправку
    wsprintf(debug, L"[TRAFFIC] Sending %d bytes (framed), inner=%d, path len=%d", 
             framedPacket.size(), packet.size(), path.size());
    AddLog(debug, LOG_DEBUG);
    
    // Отправляем сформированный пакет (длина + данные)
    bool result = peer->SendPacketRaw(&framedPacket[0], framedPacket.size());
    
    if (!result) {
        AddLog(L"[TRAFFIC] SendPacketRaw failed!", LOG_ERROR);
    }
    
    return result;
}

// ============================================================================
// ОТПРАВКА SESSION_ACK
// ============================================================================

bool IronSession::SendSessionAck(IronPeer* peer, const vector<BYTE>& path) {
    EnterCriticalSection(&m_lock);
    
    if (m_bClosed) {
        LeaveCriticalSection(&m_lock);
        return false;
    }
    
    // Аналогично INIT, но с типом SESSION_ACK
    BYTE ephPriv[32], ephPub[32];
    if (!GetPrecomputedKeyPair(ephPub, ephPriv)) {
        crypto_box_keypair(ephPub, ephPriv);
    }
    
    CYggdrasilCore* core = CYggdrasilCore::GetInstance();
    const BYTE* ourEdPub = core->GetKeys().publicKey;
    
    // Получаем текущее время в формате SYSTEMTIME (WinCE совместимо)
    SYSTEMTIME st;
    GetSystemTime(&st); 

    // 2. Конвертируем в FILETIME (количество 100-наносекундных интервалов с 1601 года)
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);

    // 3. Собираем 64-битное число
    unsigned long long ll = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    
    // 4. Сдвигаем эпоху с Windows (1601) на Unix (1970)
    // Разница составляет 11644473600 секунд. 
    // В 100-наносекундных интервалах это: 11644473600 * 10 000 000
    ll -= 116444736000000000ULL;

    // 5. Конвертируем 100-наносекундные интервалы в СЕКУНДЫ (деление на 10,000,000)
    // Go: time.Now().Unix() — секунды с Unix epoch
    unsigned long long timestamp = ll / 10000000ULL;
    
    // Формируем буфер для подписи (112 байт): ephPub + sendPub + nextPub + keySeq + timestamp
    BYTE toSign[112];
    memcpy(toSign, ephPub, 32);
    memcpy(toSign + 32, m_sendPub, 32);
    memcpy(toSign + 64, m_nextPub, 32);
    
    // localKeySeq (8 байт, big endian)
    toSign[96] = (BYTE)(m_localKeySeq >> 56);
    toSign[97] = (BYTE)(m_localKeySeq >> 48);
    toSign[98] = (BYTE)(m_localKeySeq >> 40);
    toSign[99] = (BYTE)(m_localKeySeq >> 32);
    toSign[100] = (BYTE)(m_localKeySeq >> 24);
    toSign[101] = (BYTE)(m_localKeySeq >> 16);
    toSign[102] = (BYTE)(m_localKeySeq >> 8);
    toSign[103] = (BYTE)(m_localKeySeq);
    
    // timestamp (8 байт, big endian)
    toSign[104] = (BYTE)(timestamp >> 56);
    toSign[105] = (BYTE)(timestamp >> 48);
    toSign[106] = (BYTE)(timestamp >> 40);
    toSign[107] = (BYTE)(timestamp >> 32);
    toSign[108] = (BYTE)(timestamp >> 24);
    toSign[109] = (BYTE)(timestamp >> 16);
    toSign[110] = (BYTE)(timestamp >> 8);
    toSign[111] = (BYTE)(timestamp);
    
    // Подписываем данные нашим приватным Ed25519 ключом
    BYTE signature[64];
    YggCrypto::Sign(core->GetKeys().privateKey, toSign, sizeof(toSign), signature);
    
    // Формируем финальный plaintext (144 байт)
    BYTE plaintext[144];
    memcpy(plaintext, signature, 64);              // Подпись (64 байта)
    memcpy(plaintext + 64, m_sendPub, 32);         // sendPub (32 байта)
    memcpy(plaintext + 96, m_nextPub, 32);         // nextPub (32 байта)
    memcpy(plaintext + 128, toSign + 96, 16);      // keySeq + timestamp (16 байт)
    
    BYTE nonceBytes[24] = {0};
    
    BYTE remoteX25519[32];
    if (crypto_sign_ed25519_pk_to_curve25519(remoteX25519, m_remoteKey) != 0) {
        LeaveCriticalSection(&m_lock);
        AddLog(L"[SESSION] Ed25519->X25519 conversion failed in ACK", LOG_ERROR);
        return false;
    }
    
    vector<BYTE> ciphertext;
    if (!BoxEncrypt(plaintext, sizeof(plaintext), nonceBytes, remoteX25519, ephPriv, ciphertext)) {
        LeaveCriticalSection(&m_lock);
        AddLog(L"[SESSION] Failed to encrypt ACK", LOG_ERROR);
        return false;
    }
    
    vector<BYTE> packet;
    packet.push_back(WIRE_TRAFFIC);
    packet.insert(packet.end(), path.begin(), path.end());
    packet.push_back(0);
    packet.insert(packet.end(), ourEdPub, ourEdPub + 32);
    packet.insert(packet.end(), m_remoteKey, m_remoteKey + 32);
    
    // ИСПРАВЛЕНИЕ: Это номер протокола Session (64), а не длина!
    packet.push_back(0x40);
    
    packet.push_back(SESSION_ACK);
    packet.insert(packet.end(), ephPub, ephPub + 32);
    packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
    
    // --- Добавляем фрейминг TCP (Uvarint длина пакета) ---
    vector<BYTE> framedPacket;
    DWORD packetLen = packet.size();
    
    while (packetLen >= 0x80) {
        framedPacket.push_back((BYTE)((packetLen & 0x7F) | 0x80));
        packetLen >>= 7;
    }
    framedPacket.push_back((BYTE)packetLen);
    
    framedPacket.insert(framedPacket.end(), packet.begin(), packet.end());
    
    LeaveCriticalSection(&m_lock);
    return peer->SendPacketRaw(&framedPacket[0], framedPacket.size());
}

// ============================================================================
// ОБРАБОТКА SESSION_INIT / SESSION_ACK
// ============================================================================

bool IronSession::HandleSessionHandshake(const BYTE* packet, DWORD len, int sessionType,
                                          const BYTE* srcKey, IronPeer* peer) {
    WCHAR debug[256];
    wsprintf(debug, L"[SESSION] HandleSessionHandshake type=%d, len=%lu", sessionType, len);
    AddLog(debug, LOG_DEBUG);
    
    if (len < 33) {
        AddLog(L"[SESSION] Handshake packet too short", LOG_ERROR);
        return false;
    }
    
    // Получаем ephemeral public key
    BYTE ephPub[32];
    memcpy(ephPub, packet + 1, 32);
    
    // Получаем encrypted data
    DWORD encryptedLen = len - 33;
    if (encryptedLen < 16) return false;
    
    const BYTE* encrypted = packet + 33;
    
    // Дешифруем используя наш X25519 приватный ключ (конвертация из Ed25519)
    CYggdrasilCore* core = CYggdrasilCore::GetInstance();
    const BYTE* ourEdPriv = core->GetKeys().privateKey;
    
    // Конвертируем Ed25519 private key в X25519 private key
    // Ed25519 expanded format: [32 bytes seed][32 bytes pub key]
    // Для X25519 нужно: hash(seed) с модификацией битов
    BYTE ourXPriv[32];
    BYTE hash[64];
    crypto_hash_sha512_tweet(hash, ourEdPriv, (unsigned int)32);  // hash только seed (первые 32 байта)
    memcpy(ourXPriv, hash, 32);
    ourXPriv[0] &= 248;  // clear bits 0,1,2
    ourXPriv[31] &= 127; // clear bit 255
    ourXPriv[31] |= 64;  // set bit 254
    
    wsprintf(debug, L"[SESSION] Ed25519->X25519 priv conversion, hash[0]=0x%02x, xpriv[0]=0x%02x", 
             hash[0], ourXPriv[0]);
    AddLog(debug, LOG_DEBUG);
    
    BYTE nonceBytes[24] = {0};
    vector<BYTE> decrypted;
    
    // Дешифруем через обертку
    if (!BoxDecrypt(encrypted, encryptedLen, nonceBytes, ephPub, ourXPriv, decrypted)) {
        AddLog(L"[SESSION] Decrypt failed in handshake", LOG_ERROR);
        return false;
    }
    
    wsprintf(debug, L"[SESSION] Decrypted %lu bytes", decrypted.size());
    AddLog(debug, LOG_DEBUG);
    
    if (decrypted.size() < 144) {
        AddLog(L"[SESSION] Decrypted data too short", LOG_ERROR);
        return false;
    }
    
    // Извлекаем данные
    BYTE remoteCurrentPub[32];
    BYTE remoteNextPub[32];
    // KeySeq: 8 bytes big-endian at offset 128
    unsigned long long remoteKeySeq = 
        ((unsigned long long)decrypted[128] << 56) | 
        ((unsigned long long)decrypted[129] << 48) |
        ((unsigned long long)decrypted[130] << 40) | 
        ((unsigned long long)decrypted[131] << 32) |
        ((unsigned long long)decrypted[132] << 24) | 
        ((unsigned long long)decrypted[133] << 16) |
        ((unsigned long long)decrypted[134] << 8) | 
        (unsigned long long)decrypted[135];
    
    memcpy(remoteCurrentPub, &decrypted[64], 32);
    memcpy(remoteNextPub, &decrypted[96], 32);
    
    EnterCriticalSection(&m_lock);
    
    // Если TCP уже ESTABLISHED и пришёл INIT с теми же ключами — это ретрансмит,
    // просто отправляем ACK без ротации. Если ключи другие — сервер переинициализировался,
    // нужно принять новые ключи (TCP при этом сбросится при следующем запросе).
    if (m_tcpState == TCP_ESTABLISHED) {
        if (sessionType == SESSION_INIT) {
            if (memcmp(m_remoteCurrentPub, remoteCurrentPub, 32) == 0) {
                // Те же ключи — просто ACK
                LeaveCriticalSection(&m_lock);
                NodeRoute* route = peer->GetRoute(peer->GetKeyPrefix(srcKey));
                vector<BYTE> path;
                if (route && route->path.size() > 0) {
                    path = route->path;
                    delete route;
                } else {
                    path.push_back(0);
                }
                SendSessionAck(peer, path);
                AddLog(L"[SESSION] ESTABLISHED: Re-sent ACK (same keys), skipped rotation", LOG_DEBUG);
                return true;
            }
            // Разные ключи — сервер переинициализировался, принимаем и продолжаем
            AddLog(L"[SESSION] ESTABLISHED: New keys from server, accepting", LOG_WARN);
        } else {
            LeaveCriticalSection(&m_lock);
            AddLog(L"[SESSION] ESTABLISHED: Ignoring ACK (session active)", LOG_DEBUG);
            return true;
        }
    }

    // Если уже готовы и пришел повторный пакет с теми же ключами
    if (m_bReady && memcmp(m_remoteCurrentPub, remoteCurrentPub, 32) == 0) {
        if (sessionType == SESSION_INIT) {
            // Просто отправляем ACK заново, не ротируя ключи
            LeaveCriticalSection(&m_lock);
            NodeRoute* route = peer->GetRoute(peer->GetKeyPrefix(srcKey));
            vector<BYTE> path;
            if (route && route->path.size() > 0) {
                path = route->path;
                delete route;
            } else {
                path.push_back(0);
            }
            SendSessionAck(peer, path);
            AddLog(L"[SESSION] Re-sent ACK for duplicate INIT", LOG_DEBUG);
            return true;
        } else {
            // ACK пришел повторно - игнорируем
            LeaveCriticalSection(&m_lock);
            AddLog(L"[SESSION] Ignoring duplicate ACK", LOG_DEBUG);
            return true;
        }
    }
    
    // Сохраняем ключи
    memcpy(m_remoteCurrentPub, remoteCurrentPub, 32);
    memcpy(m_remoteNextPub, remoteNextPub, 32);
    m_remoteKeySeq = remoteKeySeq;
    
    // Ротируем наши ключи и вычисляем shared secrets
    RotateKeys();
    FixShared(0, m_sendNonce);
    
    // Если это INIT - отправляем ACK
    if (sessionType == SESSION_INIT) {
        // Получаем путь из routing table
        NodeRoute* route = peer->GetRoute(peer->GetKeyPrefix(srcKey));
        vector<BYTE> path;
        if (route && route->path.size() > 0) {
            path = route->path;
            delete route;
        } else {
            path.push_back(0);
        }
        
        LeaveCriticalSection(&m_lock);
        SendSessionAck(peer, path);
        EnterCriticalSection(&m_lock);
    }
    
    m_bReady = true;
    m_decryptionErrors = 0;
    m_lastActivity = GetTickCount();   // Сессия активна после handshake
    m_lastRotation = GetTickCount();   // Сброс таймера ротации — после handshake ключи уже свежие

    // NOTE: TCP state остается CLOSED! ESTABLISHED устанавливается только при получении TCP SYN-ACK

    LeaveCriticalSection(&m_lock);

    wsprintf(debug, L"[SESSION] Ready! Local KeySeq=%llu, Remote KeySeq=%llu",
             m_localKeySeq, m_remoteKeySeq);
    AddLog(debug, LOG_SUCCESS);
    
    return true;
}
// ============================================================================
// ОТПРАВКА SESSION_TRAFFIC
// ============================================================================

bool IronSession::SendTraffic(IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len) {
    EnterCriticalSection(&m_lock);
    
    if (m_bClosed || !m_bReady) {
        LeaveCriticalSection(&m_lock);
        return false;
    }
    
    // Обновляем активность при отправке
    m_lastActivity = GetTickCount();

    // Увеличиваем nonce
    m_sendNonce++;
    
    // Проверяем переполнение nonce
    if (m_sendNonce == 0) {
        AddLog(L"[SESSION] Nonce overflow, rotating keys", LOG_INFO);
        RotateKeys();
        FixShared(0, 0);
        m_sendNonce = 1;
        
        // Обновляем трекер
        CYggdrasilCore* core = CYggdrasilCore::GetInstance();
        // TODO: обновить keySeqTracker
    }
    
    // Формируем plaintext: [nextPub][CORE_TYPE_TRAFFIC][IPv6 packet]
    vector<BYTE> plaintext;
    plaintext.insert(plaintext.end(), m_nextPub, m_nextPub + 32);
    plaintext.push_back(CORE_TYPE_TRAFFIC);
    plaintext.insert(plaintext.end(), data, data + len);
    
    // Nonce (24 байта, последние 4 - sendNonce в big endian, остальные 0)
    BYTE nonceBytes[24] = {0};
    nonceBytes[20] = (BYTE)(m_sendNonce >> 24);
    nonceBytes[21] = (BYTE)(m_sendNonce >> 16);
    nonceBytes[22] = (BYTE)(m_sendNonce >> 8);
    nonceBytes[23] = (BYTE)(m_sendNonce);
    
    // Шифруем через обертку
    vector<BYTE> ciphertext;
    if (!BoxEncryptFast(&plaintext[0], plaintext.size(), nonceBytes, m_sendShared, ciphertext)) {
        LeaveCriticalSection(&m_lock);
        return false;
    }
    
    // Формируем пакет
    vector<BYTE> packet;
    packet.push_back(WIRE_TRAFFIC);
    packet.insert(packet.end(), path.begin(), path.end());
    packet.push_back(0);  // switch port
    
    CYggdrasilCore* core = CYggdrasilCore::GetInstance();
    const BYTE* ourEdPub = core->GetKeys().publicKey;
    packet.insert(packet.end(), ourEdPub, ourEdPub + 32);
    packet.insert(packet.end(), m_remoteKey, m_remoteKey + 32);
    
    // Номер протокола Session: 0x40 (64)
    packet.push_back(0x40);
    
    // SESSION_TRAFFIC type
    packet.push_back(SESSION_TRAFFIC);
    
    // localKeySeq (varint, полный цикл)
    {
        unsigned long long v = m_localKeySeq;
        while (v >= 0x80) {
            packet.push_back((BYTE)((v & 0x7F) | 0x80));
            v >>= 7;
        }
        packet.push_back((BYTE)v);
    }

    // remoteKeySeq (varint, полный цикл)
    {
        unsigned long long v = m_remoteKeySeq;
        while (v >= 0x80) {
            packet.push_back((BYTE)((v & 0x7F) | 0x80));
            v >>= 7;
        }
        packet.push_back((BYTE)v);
    }
    
    // sendNonce (varint)
    if (m_sendNonce < 0x80) {
        packet.push_back((BYTE)m_sendNonce);
    } else {
        DWORD n = m_sendNonce;
        while (n >= 0x80) {
            packet.push_back((BYTE)((n & 0x7F) | 0x80));
            n >>= 7;
        }
        packet.push_back((BYTE)n);
    }
    
    // Ciphertext
    packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
    
    // --- Добавляем фрейминг TCP (Uvarint длина пакета) ---
    vector<BYTE> framedPacket;
    DWORD packetLen = packet.size();
    
    // Пишем длину в формате Uvarint
    while (packetLen >= 0x80) {
        framedPacket.push_back((BYTE)((packetLen & 0x7F) | 0x80));
        packetLen >>= 7;
    }
    framedPacket.push_back((BYTE)packetLen);
    
    // Копируем сам пакет после длины
    framedPacket.insert(framedPacket.end(), packet.begin(), packet.end());
    
    LeaveCriticalSection(&m_lock);
    
    // Отправляем сформированный пакет (длина + данные)
    return peer->SendPacketRaw(&framedPacket[0], framedPacket.size());
}

// ============================================================================
// ОБРАБОТКА ВХОДЯЩЕГО SESSION_TRAFFIC
// ============================================================================

bool IronSession::HandleSessionTraffic(const BYTE* packet, DWORD len, IronPeer* peer) {
    WCHAR debug[256];
    wsprintf(debug, L"[TRAFFIC] HandleSessionTraffic called, len=%lu, ready=%d, closed=%d", 
             len, m_bReady, m_bClosed);
    AddLog(debug, LOG_INFO);
    
    if (!m_bReady) {
        AddLog(L"[TRAFFIC] Session not ready, dropping packet", LOG_WARN);
        return false;
    }
    if (m_bClosed) {
        AddLog(L"[TRAFFIC] Session closed, dropping packet", LOG_WARN);
        return false;
    }
    
    // Если TCP сессия закрыта И не в процессе нового подключения — игнорируем
    // (SYN_SENT допускает приём SYN-ACK даже после предыдущего FIN_WAIT/CLOSED)
    if (m_tcpState == TCP_CLOSED) {
        AddLog(L"[TRAFFIC] TCP closed, dropping packet", LOG_DEBUG);
        return false;
    }
    
    EnterCriticalSection(&m_lock);
    
    wsprintf(debug, L"[TRAFFIC] Processing packet, len=%lu, localSeq=%I64u, remoteSeq=%I64u", 
             len, m_localKeySeq, m_remoteKeySeq);
    AddLog(debug, LOG_DEBUG);
    
    // Парсим: [type][localKeySeq(varint)][remoteKeySeq(varint)][nonce(varint)][ciphertext]
    DWORD pos = 1;  // пропускаем type
    
    // Читаем localKeySeq (varint)
    DWORD receivedLocalKeySeq = 0;
    int shift = 0;
    while (pos < len) {
        BYTE b = packet[pos++];
        receivedLocalKeySeq |= (DWORD)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    
    // Читаем remoteKeySeq (varint)
    DWORD receivedRemoteKeySeq = 0;
    shift = 0;
    while (pos < len) {
        BYTE b = packet[pos++];
        receivedRemoteKeySeq |= (DWORD)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    
    // Читаем nonce (varint)
    DWORD nonce = 0;
    shift = 0;
    while (pos < len) {
        BYTE b = packet[pos++];
        nonce |= (DWORD)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    
    // Оставшееся - ciphertext
    if (pos >= len) {
        LeaveCriticalSection(&m_lock);
        return false;
    }
    DWORD cipherLen = len - pos;
    const BYTE* ciphertext = packet + pos;
    
    // Логируем что пришло и что ожидаем
    wsprintf(debug, L"[TRAFFIC] recvLocalSeq=%lu, recvRemoteSeq=%lu, nonce=%lu", 
             receivedLocalKeySeq, receivedRemoteKeySeq, nonce);
    AddLog(debug, LOG_DEBUG);
    wsprintf(debug, L"[TRAFFIC] our localSeq=%I64u, remoteSeq=%I64u, recvNonce=%lu", 
             m_localKeySeq, m_remoteKeySeq, m_recvNonce);
    AddLog(debug, LOG_DEBUG);
    
    // Определяем какие ключи использовать
    bool fromCurrent = (receivedLocalKeySeq == m_remoteKeySeq);
    bool fromNext = (receivedLocalKeySeq == m_remoteKeySeq + 1);
    bool toRecv = (receivedRemoteKeySeq + 1 == m_localKeySeq);
    bool toSend = (receivedRemoteKeySeq == m_localKeySeq);
    
    wsprintf(debug, L"[TRAFFIC] fromCurrent=%d, fromNext=%d, toRecv=%d, toSend=%d",
             fromCurrent, fromNext, toRecv, toSend);
    AddLog(debug, LOG_DEBUG);
    
    // Используем заранее вычисленные shared keys для быстрой дешифровки
    const BYTE* sharedKeyToUse = NULL;
    DWORD* noncePtr = NULL;
    bool needsRotation = false;
    
    if (fromCurrent && toRecv) {
        if (nonce <= m_recvNonce) {
            LeaveCriticalSection(&m_lock);
            return false;  // Replay
        }
        sharedKeyToUse = m_recvShared;
        noncePtr = &m_recvNonce;
    } else if (fromNext && toSend) {
        if (nonce <= m_nextSendNonce) {
            LeaveCriticalSection(&m_lock);
            return false;
        }
        sharedKeyToUse = m_nextSendShared;
        noncePtr = &m_nextSendNonce;
        needsRotation = true;
    } else if (fromNext && toRecv) {
        if (nonce <= m_nextRecvNonce) {
            LeaveCriticalSection(&m_lock);
            return false;
        }
        sharedKeyToUse = m_nextRecvShared;
        noncePtr = &m_nextRecvNonce;
        needsRotation = true;
    } else {
        // KeySeq mismatch — шлём SESSION_INIT для ресинхронизации (как в Go)
        wsprintf(debug, L"[TRAFFIC] KeySeq mismatch: pkt localSeq=%lu remoteSeq=%lu, our localSeq=%I64u remoteSeq=%I64u",
                 receivedLocalKeySeq, receivedRemoteKeySeq, m_localKeySeq, m_remoteKeySeq);
        AddLog(debug, LOG_WARN);
        LeaveCriticalSection(&m_lock);

        NodeRoute* route = peer->GetRoute(peer->GetKeyPrefix(m_remoteKey));
        vector<BYTE> path;
        if (route && route->path.size() > 0) {
            path = route->path;
            delete route;
        } else {
            path.push_back(0);
        }
        SendSessionInit(peer, path);
        return false;
    }
    
    // Формируем nonce (24 байта)
    BYTE nonceBytes[24] = {0};
    nonceBytes[20] = (BYTE)(nonce >> 24);
    nonceBytes[21] = (BYTE)(nonce >> 16);
    nonceBytes[22] = (BYTE)(nonce >> 8);
    nonceBytes[23] = (BYTE)(nonce);
    
    // Дешифруем через БЫСТРУЮ обертку (afternm - без скалярного умножения!)
    vector<BYTE> plaintext;
    if (!BoxDecryptFast(ciphertext, cipherLen, nonceBytes, sharedKeyToUse, plaintext)) {
        m_decryptionErrors++;
        LeaveCriticalSection(&m_lock);
        
        if (m_decryptionErrors >= MAX_DECRYPTION_ERRORS) {
            // Переотправляем INIT для восстановления
            vector<BYTE> path;
            path.push_back(0);
            SendSessionInit(peer, path);
        }
        return false;
    }
    
    m_decryptionErrors = 0;
    *noncePtr = nonce;
    m_lastActivity = GetTickCount();  // Обновляем активность при успешном recv

    wsprintf(debug, L"[TRAFFIC] Decrypted OK, plaintext=%lu bytes", plaintext.size());
    AddLog(debug, LOG_SUCCESS);
    
    // Извлекаем их nextPub и данные
    if (plaintext.size() < 33) {
        LeaveCriticalSection(&m_lock);
        return false;
    }
    
    BYTE theirNextPub[32];
    memcpy(theirNextPub, &plaintext[0], 32);
    BYTE coreType = plaintext[32];
    
    // Ротация ключей только по таймеру (не при каждом пакете!)
    // Это предотвращает рассинхронизацию с сервером
    if (needsRotation && (GetTickCount() - m_lastRotation > KEY_ROTATION_INTERVAL)) {
        PerformKeyRotation(theirNextPub, nonce);
    }
    
    LeaveCriticalSection(&m_lock);
    
    // Обрабатываем данные
    wsprintf(debug, L"[TRAFFIC] coreType=0x%02x, size=%lu", coreType, plaintext.size());
    AddLog(debug, LOG_INFO);
    
    if (coreType == CORE_TYPE_TRAFFIC && plaintext.size() > 33) {
        const BYTE* ipv6Packet = &plaintext[33];
        DWORD ipv6Len = plaintext.size() - 33;
        
        wsprintf(debug, L"[TRAFFIC] Processing IPv6 packet, len=%lu", ipv6Len);
        AddLog(debug, LOG_INFO);
        
        NodeRoute* route = peer->GetRoute(peer->GetKeyPrefix(m_remoteKey));
        vector<BYTE> path;
        if (route && route->path.size() > 0) {
            path = route->path;
            delete route;
        } else {
            path.push_back(0);
        }
        
        ProcessIncomingTCP(peer, path, ipv6Packet, ipv6Len);
    } else if (coreType != CORE_TYPE_TRAFFIC) {
        wsprintf(debug, L"[TRAFFIC] Unexpected coreType: 0x%02x", coreType);
        AddLog(debug, LOG_WARN);
    }
    
    return true;
}

// ============================================================================
// TCP ОБРАБОТКА
// ============================================================================

void IronSession::SendSYN(IronPeer* peer, const vector<BYTE>& path) {
    EnterCriticalSection(&m_lock);
    if (m_synSent || m_bClosed) {
        LeaveCriticalSection(&m_lock);
        AddLog(L"[TCP] SYN not sent: already sent or closed", LOG_WARN);
        return;
    }
    m_synSent = true;
    m_tcpState = TCP_SYN_SENT;
    DWORD seq = m_localSeq;
    m_localSeq = (m_localSeq + 1) & 0xFFFFFFFF;
    LeaveCriticalSection(&m_lock);
    
    // Создаем TCP SYN пакет
    BYTE empty[1] = {0};
    DWORD dummy;
    
    WCHAR debug[256];
    wsprintf(debug, L"[TCP] Sending SYN seq=%lu, path len=%d", seq, path.size());
    AddLog(debug, LOG_INFO);
    
    CreateAndSendPacket(peer, path, true, false, false, false, seq, 0, empty, 0, dummy);
}

// Отправка SYN-пакета без проверки состояния — вызывается после TryClaimSynInitiator,
// который уже атомарно сбросил TCP-состояние и пометил m_synSent=true.
void IronSession::SendSYNPacket(IronPeer* peer, const vector<BYTE>& path) {
    DWORD seq;
    EnterCriticalSection(&m_lock);
    seq = m_localSeq;
    m_localSeq = (m_localSeq + 1) & 0xFFFFFFFF;
    LeaveCriticalSection(&m_lock);

    BYTE empty[1] = {0};
    DWORD dummy;
    WCHAR debug[256];
    wsprintf(debug, L"[TCP] Sending SYN seq=%lu, path len=%d", seq, path.size());
    AddLog(debug, LOG_INFO);
    CreateAndSendPacket(peer, path, true, false, false, false, seq, 0, empty, 0, dummy);
}

void IronSession::SendACK(IronPeer* peer, const vector<BYTE>& path, DWORD ackNum) {
    if (m_bClosed) return;
    
    BYTE empty[1] = {0};
    DWORD dummy;
    CreateAndSendPacket(peer, path, false, true, false, false, m_localSeq, ackNum, empty, 0, dummy);
}

void IronSession::SendDupACK(IronPeer* peer, const vector<BYTE>& path, DWORD ackNum) {
    if (m_bClosed) return;
    
    WCHAR debug[256];
    wsprintf(debug, L"[TCP] Sending duplicate ACK for seq=%lu", ackNum);
    AddLog(debug, LOG_DEBUG);
    
    BYTE empty[1] = {0};
    DWORD dummy;
    CreateAndSendPacket(peer, path, false, true, false, false, m_localSeq, ackNum, empty, 0, dummy);
}

void IronSession::SendFIN(IronPeer* peer, const vector<BYTE>& path) {
    if (m_bClosed) return;
    
    // Не отправляем FIN если уже закрыли или закрываем соединение
    if (m_tcpState == TCP_FIN_WAIT || m_tcpState == TCP_CLOSED) {
        return;
    }
    
    AddLog(L"[TCP] Sending FIN", LOG_INFO);
    
    EnterCriticalSection(&m_lock);
    if (m_tcpState == TCP_ESTABLISHED) {
        m_tcpState = TCP_FIN_WAIT;
    }
    LeaveCriticalSection(&m_lock);
    
    BYTE empty[1] = {0};
    DWORD dummy;
    CreateAndSendPacket(peer, path, false, false, false, true, m_localSeq, m_nextExpectedSeq, empty, 0, dummy);
}

void IronSession::SendData(IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len) {
    if (m_bClosed) return;
    
    EnterCriticalSection(&m_lock);
    DWORD seq = m_localSeq;
    DWORD ack = m_nextExpectedSeq; // Читаем под защитой блокировки
    LeaveCriticalSection(&m_lock);
    
    DWORD dummy;
    
    WCHAR debug[256];
    wsprintf(debug, L"[TCP] SendData: %lu bytes, seq=%lu, ack=%lu", len, seq, ack);
    AddLog(debug, LOG_DEBUG);
    
    CreateAndSendPacket(peer, path, false, true, true, false, seq, ack, data, len, dummy);
    
    EnterCriticalSection(&m_lock);
    m_localSeq = (m_localSeq + len) & 0xFFFFFFFF;
    LeaveCriticalSection(&m_lock);
}

void IronSession::QueueOrSendData(IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len) {
    EnterCriticalSection(&m_lock);
    
    if (m_bClosed) {
        LeaveCriticalSection(&m_lock);
        AddLog(L"[TCP] QueueOrSendData: session closed, dropping data", LOG_WARN);
        return;
    }
    
    WCHAR debug[256];
    
    if (m_tcpState == TCP_CLOSED) {
        // Сохраняем данные и отправляем SYN
        vector<BYTE> copy(data, data + len);
        m_pendingData.insert(m_pendingData.end(), copy.begin(), copy.end());
        wsprintf(debug, L"[TCP] QueueOrSendData: %lu bytes buffered (state=CLOSED), pending=%lu", 
                 len, m_pendingData.size());
        AddLog(debug, LOG_DEBUG);
        m_tcpState = TCP_SYN_SENT;
        LeaveCriticalSection(&m_lock);
        SendSYN(peer, path);
    } else if (m_tcpState == TCP_SYN_SENT) {
        // Ждем установления соединения
        vector<BYTE> copy(data, data + len);
        m_pendingData.insert(m_pendingData.end(), copy.begin(), copy.end());
        wsprintf(debug, L"[TCP] QueueOrSendData: %lu bytes buffered (state=SYN_SENT), pending=%lu", 
                 len, m_pendingData.size());
        AddLog(debug, LOG_DEBUG);
        LeaveCriticalSection(&m_lock);
    } else if (m_tcpState == TCP_ESTABLISHED) {
        LeaveCriticalSection(&m_lock);
        wsprintf(debug, L"[TCP] QueueOrSendData: %lu bytes sent (state=ESTABLISHED)", len);
        AddLog(debug, LOG_DEBUG);
        SendData(peer, path, data, len);
    } else {
        wsprintf(debug, L"[TCP] QueueOrSendData: %lu bytes dropped (state=%d)", len, m_tcpState);
        AddLog(debug, LOG_WARN);
        LeaveCriticalSection(&m_lock);
    }
}

BYTE* IronSession::CreateAndSendPacket(IronPeer* peer, const vector<BYTE>& path,
                                       bool syn, bool ack, bool psh, bool fin,
                                       DWORD seqNum, DWORD ackNum, const BYTE* data, DWORD dataLen,
                                       DWORD& outPacketLen) {
    EnterCriticalSection(&m_lock);
    
    if (!m_bReady || m_bClosed) {
        LeaveCriticalSection(&m_lock);
        return NULL;
    }
    
    // Получаем ключи
    CYggdrasilCore* core = CYggdrasilCore::GetInstance();
    const BYTE* srcIPv6 = core->GetIPv6();
    const BYTE* dstIPv6 = m_remoteIPv6;
    WORD srcPort = m_sourcePort;
    WORD dstPort = m_targetPort;
    
    LeaveCriticalSection(&m_lock);
    
    // Используем IPv6Packet для создания пакета (как в Java)
    vector<BYTE> packet = IPv6Packet::wrapTCP(srcIPv6, dstIPv6, srcPort, dstPort,
                                               syn, ack, psh, fin, seqNum, ackNum, data, dataLen);
    
    WCHAR debug[256];
    wsprintf(debug, L"[TCP] Created packet via IPv6Packet: %d bytes, syn=%d, ack=%d", 
             packet.size(), syn, ack);
    AddLog(debug, LOG_DEBUG);
    
    // Отправляем через SendTraffic
    SendTraffic(peer, path, &packet[0], packet.size());
    
    outPacketLen = packet.size();
    return NULL;
}

void IronSession::ProcessIncomingTCP(IronPeer* peer, const vector<BYTE>& path, 
                                      const BYTE* ipv6Packet, DWORD len) {
    WCHAR debug[256];
    
    if (len < 40) return;
    
    int payloadLen = ((ipv6Packet[4] & 0xFF) << 8) | (ipv6Packet[5] & 0xFF);
    if (payloadLen < 20) return;
    
    int tcpStart = 40;
    DWORD seqNum = ((DWORD)ipv6Packet[tcpStart + 4] << 24) |
                   ((DWORD)ipv6Packet[tcpStart + 5] << 16) |
                   ((DWORD)ipv6Packet[tcpStart + 6] << 8) |
                   (DWORD)ipv6Packet[tcpStart + 7];
    DWORD ackNum = ((DWORD)ipv6Packet[tcpStart + 8] << 24) |
                   ((DWORD)ipv6Packet[tcpStart + 9] << 16) |
                   ((DWORD)ipv6Packet[tcpStart + 10] << 8) |
                   (DWORD)ipv6Packet[tcpStart + 11];
    
    BYTE flags = ipv6Packet[tcpStart + 13];
    bool isFin = (flags & 0x01) != 0;
    bool isSyn = (flags & 0x02) != 0;
    bool isRst = (flags & 0x04) != 0;
    bool isAck = (flags & 0x10) != 0;
    
    int dataOffset = ((ipv6Packet[tcpStart + 12] & 0xF0) >> 4) * 4;
    int tcpPayloadLen = payloadLen - dataOffset;
    
    EnterCriticalSection(&m_lock);
    
    wsprintf(debug, L"[TCP] State=%d flags=0x%02x syn=%d ack=%d psh=%d fin=%d rst=%d payloadLen=%d seq=%lu ack=%lu",
             m_tcpState, flags, (int)isSyn, (int)isAck, (int)((flags&0x08)!=0),
             (int)isFin, (int)isRst, tcpPayloadLen, seqNum, ackNum);
    AddLog(debug, LOG_DEBUG);
    
    // Обработка SYN-ACK (только в состоянии SYN_SENT)
    if (m_tcpState == TCP_SYN_SENT && isAck) {
        wsprintf(debug, L"[TCP] SYN_SENT got ACK: ackNum=%lu, localSeq=%lu, isSyn=%d, payloadLen=%d",
                 ackNum, m_localSeq, (int)isSyn, tcpPayloadLen);
        AddLog(debug, LOG_DEBUG);

        // Проверяем что ackNum соответствует нашему SYN — защита от запоздалых пакетов
        if (ackNum != m_localSeq) {
            wsprintf(debug, L"[TCP] SYN_SENT: ackNum=%lu != localSeq=%lu, discarding stale packet", ackNum, m_localSeq);
            AddLog(debug, LOG_WARN);
            LeaveCriticalSection(&m_lock);
            return;
        }

        m_remoteSeq = seqNum;
        m_nextExpectedSeq = (seqNum + (isSyn ? 1 : 0)) & 0xFFFFFFFF;
        if (m_nextExpectedSeq == 0) m_nextExpectedSeq = 1;

        m_remoteAck = ackNum;
        m_tcpState = TCP_ESTABLISHED;

        LeaveCriticalSection(&m_lock);
        SendACK(peer, path, m_nextExpectedSeq);

        EnterCriticalSection(&m_lock);
        vector<BYTE> pending = m_pendingData;
        m_pendingData.clear();
        LeaveCriticalSection(&m_lock);

        if (pending.size() > 0) {
            SendData(peer, path, &pending[0], pending.size());
        }

        // Если в этом же пакете есть данные — обрабатываем их ниже
        if (tcpPayloadLen <= 0) return;
        EnterCriticalSection(&m_lock);
    }

    if (m_tcpState != TCP_ESTABLISHED && m_tcpState != TCP_FIN_WAIT) {
        LeaveCriticalSection(&m_lock);
        return;
    }
    
    // Обработка данных
    if (tcpPayloadLen > 0 && (tcpStart + dataOffset + tcpPayloadLen <= (int)len)) {
        const BYTE* payload = ipv6Packet + tcpStart + dataOffset;
        
        DWORD seqDiff = (seqNum - m_nextExpectedSeq) & 0xFFFFFFFF;
        if (seqDiff > MAX_SEQ_JUMP && seqDiff < 0x80000000) {
            LeaveCriticalSection(&m_lock);
            return;
        }
        
        if (IsSeqGreater(m_nextExpectedSeq, seqNum)) {
            DWORD expected = m_nextExpectedSeq;
            LeaveCriticalSection(&m_lock);
            SendACK(peer, path, expected);
            return;
        }

        if (seqNum == m_nextExpectedSeq) {
            DWORD nextSeq = (seqNum + tcpPayloadLen) & 0xFFFFFFFF;
            if (isSyn || isFin) nextSeq = (nextSeq + 1) & 0xFFFFFFFF;

            LeaveCriticalSection(&m_lock);
            DeliverToApplication(payload, tcpPayloadLen);
            EnterCriticalSection(&m_lock);

            m_nextExpectedSeq = nextSeq;
            m_dupAckCount = 0;
            
            DWORD expectedToAck = m_nextExpectedSeq;
            LeaveCriticalSection(&m_lock);
            
            ProcessReassemblyBuffer(peer, path);
            SendACK(peer, path, expectedToAck);
            
        } else if (IsSeqGreater(seqNum, m_nextExpectedSeq)) {
            if (m_dupAckCount < 3) {
                m_dupAckCount++;
                DWORD expected = m_nextExpectedSeq;
                LeaveCriticalSection(&m_lock);
                SendDupACK(peer, path, expected);
                EnterCriticalSection(&m_lock);
            }
            
            if (m_reassemblyBufferSize + tcpPayloadLen <= MAX_REASSEMBLY_SIZE) {
                vector<BYTE> copy(payload, payload + tcpPayloadLen);
                m_reassemblyBuffer[seqNum] = copy;
                if (m_reassemblyBufferSize == 0) m_oldestBufferedTime = GetTickCount();
                m_reassemblyBufferSize += tcpPayloadLen;
            }
            LeaveCriticalSection(&m_lock);
            
        } else {
            DWORD overlap = m_nextExpectedSeq - seqNum;
            if (overlap < (DWORD)tcpPayloadLen) {
                LeaveCriticalSection(&m_lock);
                DeliverToApplication(payload + overlap, tcpPayloadLen - overlap);
                EnterCriticalSection(&m_lock);
                m_nextExpectedSeq = (seqNum + tcpPayloadLen) & 0xFFFFFFFF;
                LeaveCriticalSection(&m_lock);
                ProcessReassemblyBuffer(peer, path);
            } else {
                LeaveCriticalSection(&m_lock);
            }
        }
    } else {
        // Пакет без данных (только ACK или FIN)
        if (isAck) {
            m_remoteAck = ackNum;
            if (IsSeqGreater(seqNum, m_remoteSeq)) {
                m_remoteSeq = seqNum;
                if (!IsSeqGreater(seqNum, m_nextExpectedSeq)) {
                    m_nextExpectedSeq = seqNum;
                }
            }
        }
        LeaveCriticalSection(&m_lock); // ИСПРАВЛЕНИЕ: ГАРАНТИРОВАННОЕ ОСВОБОЖДЕНИЕ БЛОКИРОВКИ!
    }
    
    // Обработка FIN (выполняется вне блокировки данных)
    if (isFin) {
        EnterCriticalSection(&m_lock);
        m_tcpState = TCP_FIN_WAIT;
        DWORD expectedAck = (seqNum + 1) & 0xFFFFFFFF;
        m_nextExpectedSeq = expectedAck;
        LeaveCriticalSection(&m_lock);
        
        SendACK(peer, path, expectedAck);
        SendFIN(peer, path);
    }
    
    CheckReassemblyTimeout();
}

void IronSession::ProcessReassemblyBuffer(IronPeer* peer, const vector<BYTE>& path) {
    EnterCriticalSection(&m_lock);
    
    while (!m_reassemblyBuffer.empty()) {
        map<DWORD, vector<BYTE> >::iterator it = m_reassemblyBuffer.begin();
        DWORD seq = it->first;
        vector<BYTE>& data = it->second;
        
        if (seq == m_nextExpectedSeq) {
            LeaveCriticalSection(&m_lock);
            DeliverToApplication(&data[0], data.size());
            
            EnterCriticalSection(&m_lock);
            m_nextExpectedSeq = (seq + data.size()) & 0xFFFFFFFF;
            m_reassemblyBufferSize -= data.size();
            m_reassemblyBuffer.erase(it);
        } else if (IsSeqGreater(seq, m_nextExpectedSeq)) {
            break;  // Ждем предыдущих пакетов
        } else {
            // Старый пакет - удаляем
            m_reassemblyBufferSize -= data.size();
            m_reassemblyBuffer.erase(it);
        }
    }
    
    if (m_reassemblyBuffer.empty()) {
        m_oldestBufferedTime = 0;
    }
    
    LeaveCriticalSection(&m_lock);
}

void IronSession::CheckReassemblyTimeout() {
    EnterCriticalSection(&m_lock);
    
    if (m_oldestBufferedTime != 0 && 
        (GetTickCount() - m_oldestBufferedTime > REASSEMBLY_TIMEOUT)) {
        
        map<DWORD, vector<BYTE> >::iterator it = m_reassemblyBuffer.begin();
        if (it != m_reassemblyBuffer.end() && IsSeqGreater(it->first, m_nextExpectedSeq)) {
            WCHAR debug[256];
            wsprintf(debug, L"[TCP] Reassembly timeout (expected %lu, got %lu), forcing reconnect",
                     m_nextExpectedSeq, it->first);
            AddLog(debug, LOG_ERROR);
            
            m_reassemblyBuffer.clear();
            m_reassemblyBufferSize = 0;
            m_oldestBufferedTime = 0;
            m_bClosed = true;
        }
    }
    
    LeaveCriticalSection(&m_lock);
}

bool IronSession::IsSeqGreater(DWORD seq1, DWORD seq2) {
    DWORD diff = (seq1 - seq2) & 0xFFFFFFFF;
    return diff > 0 && diff < 0x80000000;
}

void IronSession::DeliverToApplication(const BYTE* data, DWORD len) {
    WCHAR debug[256];
    wsprintf(debug, L"[TCP] DeliverToApplication: %lu bytes, callback=%s", 
             len, m_dataCallback ? L"yes" : L"no");
    AddLog(debug, LOG_DEBUG);
    
    // Если установлен callback - вызываем его
    if (m_dataCallback) {
        m_dataCallback(m_callbackContext, data, len);
        return;
    }
    
    // Иначе добавляем в очередь
    EnterCriticalSection(&m_recvQueueLock);
    size_t oldSize = m_recvQueue.size();
    m_recvQueue.insert(m_recvQueue.end(), data, data + len);
    wsprintf(debug, L"[TCP] Added to recvQueue: %lu bytes, queue size=%lu", len, m_recvQueue.size());
    AddLog(debug, LOG_DEBUG);
    LeaveCriticalSection(&m_recvQueueLock);
    
    // Сигнализируем о новых данных
    if (m_recvEvent) {
        SetEvent(m_recvEvent);
    }
}

void IronSession::SetDataCallback(DataCallback callback, void* context) {
    m_dataCallback = callback;
    m_callbackContext = context;
    AddLog(L"[SESSION] Data callback installed", LOG_DEBUG);
}

bool IronSession::ReadData(BYTE* buffer, DWORD maxLen, DWORD& outLen, DWORD timeoutMs) {
    outLen = 0;
    
    WCHAR debug[256];
    
    // Проверяем очередь
    EnterCriticalSection(&m_recvQueueLock);
    if (!m_recvQueue.empty()) {
        DWORD toCopy = min(maxLen, (DWORD)m_recvQueue.size());
        memcpy(buffer, &m_recvQueue[0], toCopy);
        m_recvQueue.erase(m_recvQueue.begin(), m_recvQueue.begin() + toCopy);
        outLen = toCopy;
        wsprintf(debug, L"[TCP] ReadData: %lu bytes from queue, remaining=%lu", 
                 toCopy, m_recvQueue.size());
        AddLog(debug, LOG_DEBUG);
        LeaveCriticalSection(&m_recvQueueLock);
        return true;
    }
    LeaveCriticalSection(&m_recvQueueLock);
    
    // Если callback установлен - чтение из очереди невозможно
    if (m_dataCallback) {
        AddLog(L"[TCP] ReadData: callback installed, no data in queue", LOG_DEBUG);
        return false;
    }
    
    // Ждем данные
    if (m_recvEvent) {
        DWORD result = WaitForSingleObject(m_recvEvent, timeoutMs);
        if (result != WAIT_OBJECT_0) {
            return false;  // Таймаут или ошибка
        }
        
        // Повторяем попытку чтения
        EnterCriticalSection(&m_recvQueueLock);
        if (!m_recvQueue.empty()) {
            DWORD toCopy = min(maxLen, (DWORD)m_recvQueue.size());
            memcpy(buffer, &m_recvQueue[0], toCopy);
            m_recvQueue.erase(m_recvQueue.begin(), m_recvQueue.begin() + toCopy);
            outLen = toCopy;
            LeaveCriticalSection(&m_recvQueueLock);
            return true;
        }
        LeaveCriticalSection(&m_recvQueueLock);
    }
    
    return false;
}

void IronSession::NotifyDataReceived() {
    if (m_recvEvent) {
        SetEvent(m_recvEvent);
    }
}
