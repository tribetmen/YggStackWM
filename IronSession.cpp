// IronSession.cpp - Реализация сессии Ironwood
#include "stdafx.h"
#include "IronSession.h"
#include "IronPeer.h"
#include "ygg_constants.h"
#include "YggCrypto.h"
#include "YggdrasilCore.h"
#include "IPv6Packet.h"

// Максимум данных в одном TCP-сегменте (application data внутри IPv6/TCP).
// MSS=1460 - overhead(200) = 1260
// overhead: framing(4)+WIRE_TRAFFIC(1)+path(6)+sep(1)+srcKey(32)+dstKey(32)+proto(1)+type(1)+varints(9)+nextPub(32)+CORE_TYPE(1)+MAC(16)+IPv6(40)+TCP(20) = 196 -> 200 с запасом
#define TCP_MAX_SEGMENT 1260

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

// Монотонный счётчик портов: каждый новый стрим получает уникальный порт.
// Диапазон 1025-65534, шаг 7 (простое число) — меньше шансов коллизии с OS-портами.
static volatile LONG s_nextPort = 1025;

// s_cryptoLock удалён: BoxEncryptFast/BoxDecryptFast переведены на стековые буферы,
// crypto_box_afternm/open_afternm из TweetNaCl не используют глобального состояния.

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
#define REASSEMBLY_TIMEOUT          10000         // 10 seconds (мобильное соединение с высокой задержкой)
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
// outCiphertext должен быть выделен вызывающим: plainLen + 16 байт
// Возвращает реальный размер выходных данных (plainLen + 16) или 0 при ошибке
// Потокобезопасна: всё на стеке, мьютекс не нужен.

static DWORD BoxEncryptFast(const BYTE* plaintext, DWORD plainLen,
                            const BYTE* nonce, const BYTE* sharedKey,
                            BYTE* outCiphertext) {
    // Максимум: nextPub(32) + coreType(1) + data(1320) = 1353
    BYTE padded_m[1353 + 32];
    BYTE padded_c[1353 + 32];

    if (plainLen > 1353) return 0;

    memset(padded_m, 0, 32);
    memcpy(padded_m + 32, plaintext, plainLen);
    memset(padded_c, 0, 32);

    int result = crypto_box_afternm(padded_c, padded_m, plainLen + 32, nonce, sharedKey);
    if (result != 0) return 0;

    DWORD outLen = plainLen + 16;
    memcpy(outCiphertext, padded_c + 16, outLen);
    return outLen;
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
// outPlaintext должен быть выделен вызывающим: cipherLen байт (с запасом)
// Возвращает реальный размер расшифрованных данных или 0 при ошибке
// Потокобезопасна: всё на стеке, мьютекс не нужен.
static DWORD BoxDecryptFast(const BYTE* ciphertext, DWORD cipherLen,
                            const BYTE* nonce, const BYTE* sharedKey,
                            BYTE* outPlaintext) {
    BYTE padded_c[16 + 1449];
    BYTE padded_m[16 + 1449];

    if (cipherLen < 16 || cipherLen > 1449) return 0;

    memset(padded_c, 0, 16);
    memcpy(padded_c + 16, ciphertext, cipherLen);
    memset(padded_m, 0, 32);

    int result = crypto_box_open_afternm(padded_m, padded_c, cipherLen + 16, nonce, sharedKey);
    if (result != 0) return 0;

    DWORD outLen = cipherLen - 16;
    memcpy(outPlaintext, padded_m + 32, outLen);
    return outLen;
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
    // По умолчанию запрошенный IPv6 = derived IPv6 (200::), может быть переопределён через SetRequestedIPv6
    memcpy(m_requestedIPv6, m_remoteIPv6, 16);
    
    m_targetPort = targetPort;
    m_targetPort = targetPort;
    
    m_remoteKeySeq = 0;
    m_localKeySeq = initialKeySeq;
    
    m_sendNonce = 0;
    m_recvNonce = 0;
    m_nextSendNonce = 0;
    m_nextRecvNonce = 0;
    
    // Initialize virtual streams (stream 0 is used for backward compatibility)
    for (int i = 0; i < MAX_VIRTUAL_STREAMS; i++) {
        m_streams[i].Reset((GetTickCount() % 50000) + 1024 + i);
        m_streams[i].inUse = (i == 0);  // Only stream 0 is in use initially
    }
    
    m_bReady = false;
    m_bClosed = false;
    m_lastRotation = 0;
    m_lastActivity = GetTickCount();
    m_lastInitSent = 0;
    m_decryptionErrors = 0;

    m_sessionRefCount = 1;  // volatile LONG, без Interlocked — конструктор однопоточный

    memset(m_recvShared, 0, KEY_SIZE);
    memset(m_sendShared, 0, KEY_SIZE);
    memset(m_nextSendShared, 0, KEY_SIZE);
    memset(m_nextRecvShared, 0, KEY_SIZE);

    memset(m_remoteCurrentPub, 0, KEY_SIZE);
    memset(m_remoteNextPub, 0, KEY_SIZE);

    // Callback и очередь приема (legacy)
    m_dataCallback = NULL;
    m_callbackContext = NULL;

    // UDP DNS буфер
    m_udpDnsEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    m_udpDnsPortUnreachable = false;

    InitializeCriticalSection(&m_lock);
    
    WCHAR debug[256];
    wsprintf(debug, L"[SESSION] Created for port %d, KeySeq=%llu", targetPort, initialKeySeq);
    AddLog(debug, LOG_DEBUG);
}

IronSession::~IronSession() {
    Cleanup();
    if (m_udpDnsEvent) { CloseHandle(m_udpDnsEvent); m_udpDnsEvent = NULL; }
    DeleteCriticalSection(&m_lock);
    // Virtual streams cleanup is handled by their destructors
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

VirtualStream* IronSession::GetStream(int streamId) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return NULL;
    return &m_streams[streamId];
}

bool IronSession::HasData(int streamId) const {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return false;
    return m_streams[streamId].recvQueue.size() > m_streams[streamId].recvQueueOffset;
}

TcpState IronSession::GetTcpState() const {
    // Return first active stream state, or stream 0 if none active
    for (int i = 0; i < MAX_VIRTUAL_STREAMS; i++) {
        if (m_streams[i].inUse && m_streams[i].tcpState != TCP_CLOSED) {
            return m_streams[i].tcpState;
        }
    }
    return m_streams[0].tcpState;
}

void IronSession::Close() {
    EnterCriticalSection(&m_lock);
    m_bClosed = true;
    m_bReady = false;
    // Signal all stream events
    for (int i = 0; i < MAX_VIRTUAL_STREAMS; i++) {
        if (m_streams[i].sendWindowEvent) {
            SetEvent(m_streams[i].sendWindowEvent);
        }
        if (m_streams[i].recvEvent) {
            SetEvent(m_streams[i].recvEvent);
        }
    }
    LeaveCriticalSection(&m_lock);
}

void IronSession::Cleanup() {
    EnterCriticalSection(&m_lock);
    // Cleanup all streams
    for (int i = 0; i < MAX_VIRTUAL_STREAMS; i++) {
        m_streams[i].reassemblyBuffer.clear();
        m_streams[i].reassemblyBufferSize = 0;
        m_streams[i].earlyRecvData.clear();
        m_streams[i].pendingData.clear();
        m_streams[i].tcpState = TCP_CLOSED;
        m_streams[i].dupAckCount = 0;
        m_streams[i].delayedAckCount = 0;
        m_streams[i].delayedAckTime = 0;
        m_streams[i].delayedAckSeq = 0;
        m_streams[i].recvQueue.clear();
        m_streams[i].recvQueueOffset = 0;
        if (m_streams[i].recvEvent) {
            SetEvent(m_streams[i].recvEvent);
        }
    }
    LeaveCriticalSection(&m_lock);
    
    AddLog(L"[SESSION] Cleanup completed", LOG_DEBUG);
}

// ============================================================================
// СБРОС TCP ДЛЯ ПОВТОРНОГО ИСПОЛЬЗОВАНИЯ IRONWOOD-СЕССИИ
// ============================================================================

// Атомарно: если сессия в CLOSED/FIN_WAIT — сбрасывает и возвращает true (поток-инициатор SYN).
// Если уже SYN_SENT/ESTABLISHED — возвращает false (другой поток занимается).
bool IronSession::TryClaimSynInitiator() {
    EnterCriticalSection(&m_lock);
    TcpState st = m_streams[0].tcpState;
    // Также захватываем если SYN_SENT но m_synSent=false (не должно быть, но на всякий случай)
    bool claimed = (st == TCP_CLOSED || st == TCP_FIN_WAIT);
    if (claimed) {
        // Сбрасываем состояние; m_synSent и TCP_SYN_SENT выставит SendSYN
        m_streams[0].Reset((GetTickCount() % 60000) + 1024);
        m_bClosed = false;
        // Сразу помечаем SYN_SENT чтобы конкурентные потоки не прошли сюда
        m_streams[0].tcpState = TCP_SYN_SENT;
        m_streams[0].synSent = true;
    }
    LeaveCriticalSection(&m_lock);

    if (claimed) {
        AddLog(L"[SESSION] TCP state claimed for reuse", LOG_DEBUG);
    }
    return claimed;
}

void IronSession::ResetTcpState(int streamId) {
    // streamId = -1: сбрасываем все стримы (legacy behavior для SIG_RES)
    // streamId >= 0: сбрасываем только указанный стрим
    EnterCriticalSection(&m_lock);
    
    if (streamId >= 0 && streamId < MAX_VIRTUAL_STREAMS) {
        // Reset specific stream only
        VirtualStream& s = m_streams[streamId];
        s.tcpState = TCP_CLOSED;
        s.synSent = false;
        s.serverFinReceived = false;
        s.ourFinSent = false;
        s.localSeq = GetTickCount() + streamId;
        s.remoteSeq = 0;
        s.remoteAck = 0;
        s.nextExpectedSeq = 0;
        {
            LONG p = InterlockedExchangeAdd((LONG*)&s_nextPort, 7);
            s.sourcePort = (int)(((p - 1025) % (65534 - 1025)) + 1025);
        }
        s.reassemblyBuffer.clear();
        s.reassemblyBufferSize = 0;
        s.earlyRecvData.clear();
        s.oldestBufferedTime = 0;
        s.dupAckCount = 0;
        s.delayedAckCount = 0;
        s.delayedAckTime = 0;
        s.delayedAckSeq = 0;
        s.pendingData.clear();
        s.recvQueue.clear();
        s.recvQueueOffset = 0;
        LeaveCriticalSection(&m_lock);

        WCHAR debug[256];
        wsprintf(debug, L"[SESSION] TCP reset for stream %d", streamId);
        AddLog(debug, LOG_DEBUG);
    } else {
        // Reset all streams (full reset after peer reconnect)
        for (int i = 0; i < MAX_VIRTUAL_STREAMS; i++) {
            VirtualStream& s = m_streams[i];
            s.tcpState = TCP_CLOSED;
            s.synSent = false;
            s.serverFinReceived = false;
            s.ourFinSent = false;
            s.localSeq = GetTickCount() + i;
            s.remoteSeq = 0;
            s.remoteAck = 0;
            s.nextExpectedSeq = 0;
            s.sourcePort = (GetTickCount() % 60000) + 1024 + i;
            s.reassemblyBuffer.clear();
            s.reassemblyBufferSize = 0;
            s.earlyRecvData.clear();
            s.oldestBufferedTime = 0;
            s.dupAckCount = 0;
            s.pendingData.clear();
            s.recvQueue.clear();
            s.recvQueueOffset = 0;
        }
        m_bClosed = false;
        m_bReady = false;  // HTTP не отправит SYN пока не завершится новый SESSION_INIT/ACK
        m_lastInitSent = 0;
        LeaveCriticalSection(&m_lock);
        
        AddLog(L"[SESSION] TCP state reset for ALL streams", LOG_DEBUG);
    }
}

void IronSession::ResetTcpOnly(int streamId) {
    // Сбрасываем TCP-стек для конкретного стрима — Ironwood-туннель (m_bReady) остаётся валидным.
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) streamId = 0;
    
    EnterCriticalSection(&m_lock);
    VirtualStream& s = m_streams[streamId];
    s.tcpState = TCP_CLOSED;
    s.synSent = false;
    s.serverFinReceived = false;
    s.ourFinSent = false;
    s.localSeq = GetTickCount() + streamId;
    s.remoteSeq = 0;
    s.remoteAck = 0;
    s.nextExpectedSeq = 0;
    {
        LONG p = InterlockedExchangeAdd((LONG*)&s_nextPort, 7);
        s.sourcePort = (int)(((p - 1025) % (65534 - 1025)) + 1025);
    }
    s.reassemblyBuffer.clear();
    s.reassemblyBufferSize = 0;
    s.earlyRecvData.clear();
    s.oldestBufferedTime = 0;
    s.dupAckCount = 0;
    s.delayedAckCount = 0;
    s.delayedAckTime = 0;
    s.delayedAckSeq = 0;
    s.pendingData.clear();
    s.recvQueue.clear();
    s.recvQueueOffset = 0;
    // m_bReady НЕ сбрасывается — туннель уже установлен
    m_lastInitSent = 0;
    LeaveCriticalSection(&m_lock);

    WCHAR debug[256];
    wsprintf(debug, L"[SESSION] TCP-only reset for stream %d", streamId);
    AddLog(debug, LOG_DEBUG);
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

    // Берём новую пару next из пула, fallback — генерируем напрямую
    if (!GetPrecomputedKeyPair(m_nextPub, m_nextPriv)) {
        crypto_box_keypair(m_nextPub, m_nextPriv);
    }

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
    
    // Шифруем через BoxEncrypt (plaintext=144 байт, ciphertext=144+16=160 байт)
    BYTE nonceBytes[24];
    memset(nonceBytes, 0, sizeof(nonceBytes));

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

    // Шифруем в стековый буфер (144 + 16 = 160 байт)
    BYTE cipherbuf[160];
    DWORD encStart = GetTickCount();
    {
        // BoxEncrypt: padded_m[32+144], padded_c[32+144] — всё на стеке
        BYTE padded_m[32 + 144];
        BYTE padded_c[32 + 144];
        memset(padded_m, 0, 32);
        memcpy(padded_m + 32, plaintext, 144);
        memset(padded_c, 0, 32);
        if (crypto_box(padded_c, padded_m, 32 + 144, nonceBytes, remoteX25519, ephPriv) != 0) {
            LeaveCriticalSection(&m_lock);
            AddLog(L"[SESSION] Failed to encrypt INIT", LOG_ERROR);
            return false;
        }
        memcpy(cipherbuf, padded_c + 16, 160);
    }
    DWORD encTime = GetTickCount() - encStart;

    DWORD totalTime = GetTickCount() - initStart;
    wsprintf(debug, L"[SESSION_INIT] Conversion: %lums, Encryption: %lums, TOTAL: %lums",
             convTime, encTime, totalTime);
    AddLog(debug, LOG_INFO);

    // Формируем пакет на стеке (не static: несколько сессий могут инициализироваться параллельно)
    // 1 + path(<=16) + 1 + 32 + 32 + 1 + 1 + 32(ephPub) + 160(cipher) = ~280 байт
    BYTE s_init_packet[320];
    BYTE s_init_framed[324];
    DWORD ppos = 0;

    s_init_packet[ppos++] = WIRE_TRAFFIC;
    for (DWORD i = 0; i < (DWORD)path.size(); i++) s_init_packet[ppos++] = path[i];
    s_init_packet[ppos++] = 0;
    memcpy(s_init_packet + ppos, ourEdPub, 32);   ppos += 32;
    memcpy(s_init_packet + ppos, m_remoteKey, 32); ppos += 32;
    s_init_packet[ppos++] = 0x40;
    s_init_packet[ppos++] = SESSION_INIT;
    memcpy(s_init_packet + ppos, ephPub, 32);      ppos += 32;
    memcpy(s_init_packet + ppos, cipherbuf, 160);  ppos += 160;

    DWORD fpos = 0;
    DWORD packetLen = ppos;
    while (packetLen >= 0x80) { s_init_framed[fpos++] = (BYTE)((packetLen & 0x7F) | 0x80); packetLen >>= 7; }
    s_init_framed[fpos++] = (BYTE)packetLen;
    memcpy(s_init_framed + fpos, s_init_packet, ppos);
    fpos += ppos;

    LeaveCriticalSection(&m_lock);

    wsprintf(debug, L"[TRAFFIC] Sending INIT %lu bytes (framed), path len=%d",
             fpos, (int)path.size());
    AddLog(debug, LOG_DEBUG);

    bool result = peer->SendPacketRaw(s_init_framed, fpos);
    if (!result) AddLog(L"[TRAFFIC] SendPacketRaw failed!", LOG_ERROR);
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
    
    BYTE nonceBytes[24];
    memset(nonceBytes, 0, sizeof(nonceBytes));

    BYTE remoteX25519[32];
    if (crypto_sign_ed25519_pk_to_curve25519(remoteX25519, m_remoteKey) != 0) {
        LeaveCriticalSection(&m_lock);
        AddLog(L"[SESSION] Ed25519->X25519 conversion failed in ACK", LOG_ERROR);
        return false;
    }

    // Шифруем на стеке (144 + 16 = 160 байт)
    BYTE cipherbuf[160];
    {
        BYTE padded_m[32 + 144];
        BYTE padded_c[32 + 144];
        memset(padded_m, 0, 32);
        memcpy(padded_m + 32, plaintext, 144);
        memset(padded_c, 0, 32);
        if (crypto_box(padded_c, padded_m, 32 + 144, nonceBytes, remoteX25519, ephPriv) != 0) {
            LeaveCriticalSection(&m_lock);
            AddLog(L"[SESSION] Failed to encrypt ACK", LOG_ERROR);
            return false;
        }
        memcpy(cipherbuf, padded_c + 16, 160);
    }

    BYTE s_ack_packet[320];
    BYTE s_ack_framed[324];
    DWORD ppos = 0;

    s_ack_packet[ppos++] = WIRE_TRAFFIC;
    for (DWORD i = 0; i < (DWORD)path.size(); i++) s_ack_packet[ppos++] = path[i];
    s_ack_packet[ppos++] = 0;
    memcpy(s_ack_packet + ppos, ourEdPub, 32);   ppos += 32;
    memcpy(s_ack_packet + ppos, m_remoteKey, 32); ppos += 32;
    s_ack_packet[ppos++] = 0x40;
    s_ack_packet[ppos++] = SESSION_ACK;
    memcpy(s_ack_packet + ppos, ephPub, 32);      ppos += 32;
    memcpy(s_ack_packet + ppos, cipherbuf, 160);  ppos += 160;

    DWORD fpos = 0;
    DWORD packetLen = ppos;
    while (packetLen >= 0x80) { s_ack_framed[fpos++] = (BYTE)((packetLen & 0x7F) | 0x80); packetLen >>= 7; }
    s_ack_framed[fpos++] = (BYTE)packetLen;
    memcpy(s_ack_framed + fpos, s_ack_packet, ppos);
    fpos += ppos;

    LeaveCriticalSection(&m_lock);
    return peer->SendPacketRaw(s_ack_framed, fpos);
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
    
    // X25519 private key — берём из кеша (вычислен один раз при старте)
    const BYTE* ourXPriv = core->GetXPrivKey();
    
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
    if (m_streams[0].tcpState == TCP_ESTABLISHED) {
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

    // Сбрасываем synSent у стримов в TCP_SYN_SENT: SYN был отправлен со старыми ключами,
    // после ротации сервер использует новые ключи — нужно отправить SYN заново.
    // HTTP-поток сделает retry через SYN_RETRY_INTERVAL (5 сек) и synSent=false позволит это.
    for (int i = 0; i < MAX_VIRTUAL_STREAMS; i++) {
        if (m_streams[i].tcpState == TCP_SYN_SENT) {
            m_streams[i].synSent = false;
        }
    }

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

    // Максимальный payload: TCP_MAX_SEGMENT(1260) + IPv6/TCP headers(60) = 1320.
    // При превышении Ironwood-пакет не влезет в один транспортный MSS=1460.
    if (len > 1320) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    m_lastActivity = GetTickCount();
    m_sendNonce++;

    if (m_sendNonce == 0) {
        AddLog(L"[SESSION] Nonce overflow, rotating keys", LOG_INFO);
        RotateKeys();
        FixShared(0, 0);
        m_sendNonce = 1;
    }

    // --- plaintext: [nextPub(32)][CORE_TYPE_TRAFFIC(1)][data] ---
    BYTE s_plaintext[32 + 1 + 1320];
    memcpy(s_plaintext, m_nextPub, 32);
    s_plaintext[32] = CORE_TYPE_TRAFFIC;
    memcpy(s_plaintext + 33, data, len);
    DWORD plaintextLen = 33 + len;

    // Nonce (24 байта)
    BYTE nonceBytes[24];
    memset(nonceBytes, 0, 20);
    nonceBytes[20] = (BYTE)(m_sendNonce >> 24);
    nonceBytes[21] = (BYTE)(m_sendNonce >> 16);
    nonceBytes[22] = (BYTE)(m_sendNonce >> 8);
    nonceBytes[23] = (BYTE)(m_sendNonce);

    // ciphertext = plaintext + 16 (MAC) — стек, не static: разные сессии могут вызываться параллельно
    BYTE s_ciphertext[32 + 1 + 1320 + 16];
    DWORD cipherLen = BoxEncryptFast(s_plaintext, plaintextLen, nonceBytes, m_sendShared, s_ciphertext);
    if (cipherLen == 0) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    CYggdrasilCore* core = CYggdrasilCore::GetInstance();
    const BYTE* ourEdPub = core->GetKeys().publicKey;

    // --- Собираем пакет --- стек (не static): разные сессии параллельны
    BYTE s_packet[1 + 16 + 1 + 32 + 32 + 1 + 1 + 10 + 32 + 1 + 1320 + 16];
    DWORD ppos = 0;

    s_packet[ppos++] = WIRE_TRAFFIC;
    // path
    for (DWORD i = 0; i < (DWORD)path.size(); i++)
        s_packet[ppos++] = path[i];
    s_packet[ppos++] = 0;  // switch port
    memcpy(s_packet + ppos, ourEdPub, 32);   ppos += 32;
    memcpy(s_packet + ppos, m_remoteKey, 32); ppos += 32;
    s_packet[ppos++] = 0x40;          // proto Session
    s_packet[ppos++] = SESSION_TRAFFIC;

    // localKeySeq (varint)
    {
        unsigned long long v = m_localKeySeq;
        while (v >= 0x80) { s_packet[ppos++] = (BYTE)((v & 0x7F) | 0x80); v >>= 7; }
        s_packet[ppos++] = (BYTE)v;
    }
    // remoteKeySeq (varint)
    {
        unsigned long long v = m_remoteKeySeq;
        while (v >= 0x80) { s_packet[ppos++] = (BYTE)((v & 0x7F) | 0x80); v >>= 7; }
        s_packet[ppos++] = (BYTE)v;
    }
    // sendNonce (varint)
    {
        DWORD n = m_sendNonce;
        while (n >= 0x80) { s_packet[ppos++] = (BYTE)((n & 0x7F) | 0x80); n >>= 7; }
        s_packet[ppos++] = (BYTE)n;
    }

    memcpy(s_packet + ppos, s_ciphertext, cipherLen);
    ppos += cipherLen;

    // --- Фрейминг (Uvarint длина перед пакетом) --- стек (не static)
    BYTE s_framed[4 + 1 + 16 + 1 + 32 + 32 + 1 + 1 + 10 + 32 + 1 + 1320 + 16];
    DWORD fpos = 0;
    DWORD packetLen = ppos;
    while (packetLen >= 0x80) { s_framed[fpos++] = (BYTE)((packetLen & 0x7F) | 0x80); packetLen >>= 7; }
    s_framed[fpos++] = (BYTE)packetLen;
    memcpy(s_framed + fpos, s_packet, ppos);
    fpos += ppos;

    LeaveCriticalSection(&m_lock);

    return peer->SendPacketRaw(s_framed, fpos);
}

// ============================================================================
// ОБРАБОТКА ВХОДЯЩЕГО SESSION_TRAFFIC
// ============================================================================

bool IronSession::HandleSessionTraffic(const BYTE* packet, DWORD len, IronPeer* peer) {
    if (!m_bReady) {
        return false;
    }
    if (m_bClosed) {
        return false;
    }

    // Проверяем есть ли активные или захваченные потоки
    bool hasActiveStream = false;
    for (int i = 0; i < MAX_VIRTUAL_STREAMS; i++) {
        // inUse=true означает стрим захвачен HTTP-потоком (даже если TCP_CLOSED — идёт SYN)
        if (m_streams[i].inUse) {
            hasActiveStream = true;
            break;
        }
    }

    if (!hasActiveStream) {
        // Все потоки свободны и Ironwood-сессия жива (m_bReady=true).
        // Пир ещё не знает что мы переинициализировались — шлём ему SESSION_INIT
        // чтобы он обновил наши ключи и не ждал трафика по старой сессии.
        if (m_bReady) {
            DWORD now = GetTickCount();
            if ((now - m_lastInitSent) >= 5000) {
                m_lastInitSent = now;
                NodeRoute* route = peer->GetRoute(peer->GetKeyPrefix(m_remoteKey));
                vector<BYTE> path;
                if (route && route->path.size() > 0) {
                    path = route->path;
                    delete route;
                } else {
                    path.push_back(0);
                }
                AddLog(L"[TRAFFIC] All streams CLOSED but ready — sending INIT to wake peer", LOG_DEBUG);
                SendSessionInit(peer, path);
            }
        }
        return false;
    }

    EnterCriticalSection(&m_lock);

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
    
    // Определяем какие ключи использовать
    bool fromCurrent = (receivedLocalKeySeq == m_remoteKeySeq);
    bool fromNext = (receivedLocalKeySeq == m_remoteKeySeq + 1);
    bool toRecv = (receivedRemoteKeySeq + 1 == m_localKeySeq);
    bool toSend = (receivedRemoteKeySeq == m_localKeySeq);
    
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
        {
            WCHAR debug[256];
            wsprintf(debug, L"[TRAFFIC] KeySeq mismatch: pkt localSeq=%lu remoteSeq=%lu, our localSeq=%I64u remoteSeq=%I64u",
                     receivedLocalKeySeq, receivedRemoteKeySeq, m_localKeySeq, m_remoteKeySeq);
            AddLog(debug, LOG_WARN);
        }
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
    BYTE s_plainbuf[1449];  // стек — каждая сессия работает независимо
    DWORD plainLen = BoxDecryptFast(ciphertext, cipherLen, nonceBytes, sharedKeyToUse, s_plainbuf);
    if (plainLen == 0) {
        m_decryptionErrors++;
        LeaveCriticalSection(&m_lock);

        if (m_decryptionErrors >= MAX_DECRYPTION_ERRORS) {
            vector<BYTE> path;
            path.push_back(0);
            SendSessionInit(peer, path);
        }
        return false;
    }

    m_decryptionErrors = 0;
    *noncePtr = nonce;
    m_lastActivity = GetTickCount();

    if (plainLen < 33) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    BYTE theirNextPub[32];
    memcpy(theirNextPub, s_plainbuf, 32);
    BYTE coreType = s_plainbuf[32];
    
    // DEBUG: Логгируем ВСЕ входящие пакеты (любой coreType)
    {
        WCHAR typeDbg[128];
        wsprintf(typeDbg, L"[TRAFFIC] Received: coreType=0x%02x plainLen=%lu", coreType, (unsigned long)plainLen);
        AddLog(typeDbg, LOG_DEBUG);
    }

    // Копируем IPv6 payload до LeaveCriticalSection — s_plainbuf static и может быть перезаписан
    // после выхода из секции если другой поток войдёт в HandleSessionTraffic
    BYTE ipv6buf[1449 - 33];
    DWORD ipv6Len = 0;
    if (coreType == CORE_TYPE_TRAFFIC && plainLen > 33) {
        ipv6Len = plainLen - 33;
        memcpy(ipv6buf, s_plainbuf + 33, ipv6Len);
    }

    // Ротация ключей только по таймеру (не при каждом пакете!)
    if (needsRotation && (GetTickCount() - m_lastRotation > KEY_ROTATION_INTERVAL)) {
        PerformKeyRotation(theirNextPub, nonce);
    }

    LeaveCriticalSection(&m_lock);

    if (coreType == CORE_TYPE_TRAFFIC && ipv6Len > 0) {
        const BYTE* ipv6Packet = ipv6buf;
        
        NodeRoute* route = peer->GetRoute(peer->GetKeyPrefix(m_remoteKey));
        vector<BYTE> path;
        if (route && route->path.size() > 0) {
            path = route->path;
            delete route;
        } else {
            // Маршрут не найден — ACK уйдёт по path={0}, что неправильно.
            // Логируем чтобы диагностировать.
            AddLog(L"[TCP] WARNING: no route for ACK — using fallback path {0}", LOG_WARN);
            path.push_back(0);
        }

        // UDP Next Header = 0x11 (17)
        if (ipv6Len >= 48 && ipv6Packet[6] == 0x11) {
            WORD srcPort = ((WORD)ipv6Packet[40] << 8) | ipv6Packet[41];
            if (srcPort == 53) {
                // UDP DNS ответ — кладём в буфер и сигнализируем
                WORD udpLen = ((WORD)ipv6Packet[44] << 8) | ipv6Packet[45];
                DWORD dataLen = (udpLen >= 8) ? udpLen - 8 : 0;
                if (dataLen > 0 && ipv6Len >= 48u + dataLen) {
                    EnterCriticalSection(&m_lock);
                    m_udpDnsResponse.assign(ipv6Packet + 48, ipv6Packet + 48 + dataLen);
                    LeaveCriticalSection(&m_lock);
                    if (m_udpDnsEvent) SetEvent(m_udpDnsEvent);
                    AddLog(L"[UDP] DNS response stored", LOG_DEBUG);
                } else {
                    WCHAR udpErr[128];
                    wsprintf(udpErr, L"[UDP] DNS bad len: udpLen=%d dataLen=%lu ipv6Len=%lu", udpLen, (unsigned long)dataLen, (unsigned long)ipv6Len);
                    AddLog(udpErr, LOG_WARN);
                }
            }
        } else if (ipv6Len > 0 && ipv6Packet[6] == 0x3a) {
            // ICMPv6
            if (ipv6Len >= 42) {
                BYTE icmpType = ipv6Packet[40];
                BYTE icmpCode = ipv6Packet[41];
                if (icmpType == 1) {
                    WCHAR msg[64]; wsprintf(msg, L"[ICMPv6] Unreachable code=%d", icmpCode);
                    AddLog(msg, LOG_WARN);
                    m_udpDnsPortUnreachable = true;
                    if (m_udpDnsEvent) SetEvent(m_udpDnsEvent);
                }
            }
        } else if (ipv6Len > 0) {
            ProcessIncomingTCP(peer, path, ipv6Packet, ipv6Len);
        }
    } else if (coreType != CORE_TYPE_TRAFFIC) {
        WCHAR debug[64];
        wsprintf(debug, L"[TRAFFIC] Unexpected coreType: 0x%02x", coreType);
        AddLog(debug, LOG_WARN);
    }
    
    return true;
}

// ============================================================================
// TCP ОБРАБОТКА
// ============================================================================

void IronSession::SendSYN(int streamId, IronPeer* peer, const vector<BYTE>& path) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return;
    EnterCriticalSection(&m_lock);
    if (m_bClosed) {
        LeaveCriticalSection(&m_lock);
        AddLog(L"[TCP] SYN not sent: session closed", LOG_WARN);
        return;
    }
    // Разрешаем ретрансмит SYN если уже в TCP_SYN_SENT (SYN мог потеряться в сети)
    if (m_streams[streamId].synSent && m_streams[streamId].tcpState != TCP_SYN_SENT) {
        LeaveCriticalSection(&m_lock);
        AddLog(L"[TCP] SYN not sent: already sent or closed", LOG_WARN);
        return;
    }
    bool isRetransmit = m_streams[streamId].synSent;
    m_streams[streamId].synSent = true;
    m_streams[streamId].tcpState = TCP_SYN_SENT;
    // При ретрансмите используем тот же seq (localSeq уже был инкрементирован при первом SYN)
    DWORD seq = isRetransmit ? (m_streams[streamId].localSeq - 1) & 0xFFFFFFFF
                             : m_streams[streamId].localSeq;
    if (!isRetransmit) {
        m_streams[streamId].localSeq = (m_streams[streamId].localSeq + 1) & 0xFFFFFFFF;
    }
    LeaveCriticalSection(&m_lock);
    
    // Создаем TCP SYN пакет
    BYTE empty[1] = {0};
    DWORD dummy;
    
    WCHAR debug[256];
    wsprintf(debug, isRetransmit ? L"[TCP] Retransmitting SYN seq=%lu, path len=%d"
                                 : L"[TCP] Sending SYN seq=%lu, path len=%d", seq, path.size());
    AddLog(debug, LOG_INFO);

    CreateAndSendPacket(streamId, peer, path, true, false, false, false, seq, 0, empty, 0, dummy);
}

void IronSession::SendSYN(IronPeer* peer, const vector<BYTE>& path) {
    SendSYN(0, peer, path);
}

// Отправка SYN-пакета без проверки состояния — вызывается после TryClaimSynInitiator,
// который уже атомарно сбросил TCP-состояние и пометил m_synSent=true.
void IronSession::SendSYNPacket(int streamId, IronPeer* peer, const vector<BYTE>& path) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return;
    DWORD seq;
    EnterCriticalSection(&m_lock);
    seq = m_streams[streamId].localSeq;
    m_streams[streamId].localSeq = (m_streams[streamId].localSeq + 1) & 0xFFFFFFFF;
    LeaveCriticalSection(&m_lock);

    BYTE empty[1] = {0};
    DWORD dummy;
    WCHAR debug[256];
    wsprintf(debug, L"[TCP] Sending SYN seq=%lu, path len=%d", seq, path.size());
    AddLog(debug, LOG_INFO);
    CreateAndSendPacket(streamId, peer, path, true, false, false, false, seq, 0, empty, 0, dummy);
}

void IronSession::SendSYNPacket(IronPeer* peer, const vector<BYTE>& path) {
    SendSYNPacket(0, peer, path);
}

void IronSession::SendACK(int streamId, IronPeer* peer, const vector<BYTE>& path, DWORD ackNum) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return;
    if (m_bClosed) return;

    BYTE empty[1] = {0};
    DWORD dummy;
    CreateAndSendPacket(streamId, peer, path, false, true, false, false, m_streams[streamId].localSeq, ackNum, empty, 0, dummy);
}

void IronSession::SendACK(IronPeer* peer, const vector<BYTE>& path, DWORD ackNum) {
    SendACK(0, peer, path, ackNum);
}

void IronSession::SendDupACK(int streamId, IronPeer* peer, const vector<BYTE>& path, DWORD ackNum) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return;
    if (m_bClosed) return;
    
    WCHAR debug[256];
    wsprintf(debug, L"[TCP] Sending duplicate ACK for seq=%lu", ackNum);
    AddLog(debug, LOG_DEBUG);
    
    BYTE empty[1] = {0};
    DWORD dummy;
    CreateAndSendPacket(streamId, peer, path, false, true, false, false, m_streams[streamId].localSeq, ackNum, empty, 0, dummy);
}

void IronSession::SendDupACK(IronPeer* peer, const vector<BYTE>& path, DWORD ackNum) {
    SendDupACK(0, peer, path, ackNum);
}

void IronSession::SendFIN(int streamId, IronPeer* peer, const vector<BYTE>& path) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return;
    if (m_bClosed) return;

    // Не отправляем FIN если уже закрыты (TCP_CLOSED = RST/уже завершено)
    if (m_streams[streamId].tcpState == TCP_CLOSED) {
        return;
    }

    // Если сервер уже прислал FIN (TCP_FIN_WAIT + m_serverFinReceived) — отправляем наш FIN
    // Если мы уже отправили FIN (TCP_FIN_WAIT без серверного FIN) — не повторяем
    if (m_streams[streamId].tcpState == TCP_FIN_WAIT && !m_streams[streamId].serverFinReceived) {
        return;
    }

    AddLog(L"[TCP] Sending FIN", LOG_INFO);

    EnterCriticalSection(&m_lock);
    m_streams[streamId].ourFinSent = true;
    m_streams[streamId].tcpState = TCP_FIN_WAIT;
    LeaveCriticalSection(&m_lock);
    
    BYTE empty[1] = {0};
    DWORD dummy;
    CreateAndSendPacket(streamId, peer, path, false, false, false, true, m_streams[streamId].localSeq, m_streams[streamId].nextExpectedSeq, empty, 0, dummy);
}

void IronSession::SendFIN(IronPeer* peer, const vector<BYTE>& path) {
    SendFIN(0, peer, path);
}

// Максимум данных в одном TCP-сегменте (application data внутри IPv6/TCP).
//
// Цель: весь framed Ironwood-пакет должен влезать в один транспортный TCP-сегмент
// (MSS=1460), иначе каждый пакет будет разбит на 2 сегмента и задержка удвоится.
//
// Расчёт (MSS=1460):
//   framing uvarint:  2
//   WIRE_TRAFFIC:     1
//   path (до 16):    16  (координаты дерева + завершающий 0)
//   srcKey+dstKey:   64
//   proto+type:       2
//   varints (3×):     6  (keySeq×2 + nonce, обычно 1-2 байта каждый)
//   nextPub:         32
//   CORE_TYPE:        1
//   NaCl MAC:        16
//   IPv6 header:     40
//   TCP header:      20
//   ───────────────────
//   overhead total: 200
//
//   TCP_MAX_SEGMENT = 1460 - 200 = 1260  (defined at top of file)

void IronSession::SendData(int streamId, IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return;
    if (m_bClosed) return;

    DWORD offset = 0;
    while (offset < len) {
        DWORD chunkLen = len - offset;
        if (chunkLen > TCP_MAX_SEGMENT) chunkLen = TCP_MAX_SEGMENT;

        EnterCriticalSection(&m_lock);
        DWORD seq = m_streams[streamId].localSeq;
        DWORD ack = m_streams[streamId].nextExpectedSeq;
        m_streams[streamId].localSeq = (m_streams[streamId].localSeq + chunkLen) & 0xFFFFFFFF;
        LeaveCriticalSection(&m_lock);

        DWORD dummy;
        CreateAndSendPacket(streamId, peer, path, false, true, true, false,
                            seq, ack, data + offset, chunkLen, dummy);

        offset += chunkLen;
    }
}

void IronSession::SendData(IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len) {
    SendData(0, peer, path, data, len);
}

void IronSession::QueueOrSendData(int streamId, IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return;
    EnterCriticalSection(&m_lock);

    if (m_bClosed) {
        LeaveCriticalSection(&m_lock);
        AddLog(L"[TCP] QueueOrSendData: session closed, dropping data", LOG_WARN);
        return;
    }

    if (m_streams[streamId].tcpState == TCP_CLOSED) {
        vector<BYTE> copy(data, data + len);
        m_streams[streamId].pendingData.insert(m_streams[streamId].pendingData.end(), copy.begin(), copy.end());
        m_streams[streamId].tcpState = TCP_SYN_SENT;
        LeaveCriticalSection(&m_lock);
        SendSYN(streamId, peer, path);
    } else if (m_streams[streamId].tcpState == TCP_SYN_SENT) {
        vector<BYTE> copy(data, data + len);
        m_streams[streamId].pendingData.insert(m_streams[streamId].pendingData.end(), copy.begin(), copy.end());
        LeaveCriticalSection(&m_lock);
    } else if (m_streams[streamId].tcpState == TCP_ESTABLISHED) {
        LeaveCriticalSection(&m_lock);
        SendData(streamId, peer, path, data, len);
    } else if (m_streams[streamId].tcpState == TCP_FIN_WAIT && m_streams[streamId].serverFinReceived && !m_streams[streamId].ourFinSent) {
        // Сервер прислал FIN, но мы ещё не отправили наш FIN — можно слать данные (TCP half-close)
        LeaveCriticalSection(&m_lock);
        SendData(streamId, peer, path, data, len);
    } else {
        WCHAR debug[128];
        wsprintf(debug, L"[TCP] QueueOrSendData: %lu bytes dropped (state=%d)", len, m_streams[streamId].tcpState);
        AddLog(debug, LOG_WARN);
        LeaveCriticalSection(&m_lock);
    }
}

void IronSession::QueueOrSendData(IronPeer* peer, const vector<BYTE>& path, const BYTE* data, DWORD len) {
    QueueOrSendData(0, peer, path, data, len);
}

BYTE* IronSession::CreateAndSendPacket(int streamId, IronPeer* peer, const vector<BYTE>& path,
                                       bool syn, bool ack, bool psh, bool fin,
                                       DWORD seqNum, DWORD ackNum, const BYTE* data, DWORD dataLen,
                                       DWORD& outPacketLen) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return NULL;
    EnterCriticalSection(&m_lock);

    if (!m_bReady || m_bClosed) {
        LeaveCriticalSection(&m_lock);
        return NULL;
    }

    CYggdrasilCore* core = CYggdrasilCore::GetInstance();
    const BYTE* srcIPv6 = core->GetIPv6();
    BYTE dstIPv6[16];
    memcpy(dstIPv6, m_requestedIPv6, 16);
    WORD srcPort = (WORD)m_streams[streamId].sourcePort;
    WORD dstPort = (WORD)m_targetPort;

    LeaveCriticalSection(&m_lock);

    // Собираем IPv6/TCP пакет прямо в стековый буфер — без heap аллокаций
    // Максимум: IPv6(40) + TCP(20) + data(1260) = 1320 байт
    BYTE pktBuf[1320];
    DWORD pktLen = 0;

    // --- TCP сегмент (сначала строим на месте offset 40) ---
    BYTE* tcp = pktBuf + 40;
    DWORD tcpLen = 20 + dataLen;

    // Ports
    tcp[0] = (BYTE)(srcPort >> 8);   tcp[1] = (BYTE)(srcPort);
    tcp[2] = (BYTE)(dstPort >> 8);   tcp[3] = (BYTE)(dstPort);
    // Seq
    tcp[4] = (BYTE)(seqNum >> 24);   tcp[5] = (BYTE)(seqNum >> 16);
    tcp[6] = (BYTE)(seqNum >> 8);    tcp[7] = (BYTE)(seqNum);
    // Ack
    tcp[8] = (BYTE)(ackNum >> 24);   tcp[9] = (BYTE)(ackNum >> 16);
    tcp[10] = (BYTE)(ackNum >> 8);   tcp[11] = (BYTE)(ackNum);
    // Data offset = 5 (20 bytes header)
    tcp[12] = 0x50;
    // Flags
    {
        BYTE flags = 0;
        if (fin) flags |= 0x01;
        if (syn) flags |= 0x02;
        if (psh) flags |= 0x08;
        if (ack) flags |= 0x10;
        tcp[13] = flags;
    }
    // Window size = 65535
    tcp[14] = 0xFF; tcp[15] = 0xFF;
    // Checksum placeholder
    tcp[16] = 0x00; tcp[17] = 0x00;
    // Urgent pointer
    tcp[18] = 0x00; tcp[19] = 0x00;
    // Data
    if (dataLen > 0 && data != NULL) {
        memcpy(tcp + 20, data, dataLen);
    }

    // --- IPv6 header (40 bytes) ---
    BYTE* ip6 = pktBuf;
    // Version=6, TC=0, Flow=0
    ip6[0] = 0x60; ip6[1] = 0x00; ip6[2] = 0x00; ip6[3] = 0x00;
    // Payload length
    ip6[4] = (BYTE)(tcpLen >> 8); ip6[5] = (BYTE)(tcpLen);
    // Next header = TCP(6), Hop limit = 64
    ip6[6] = 0x06; ip6[7] = 64;
    // Source address
    memcpy(ip6 + 8, srcIPv6, 16);
    // Destination address
    memcpy(ip6 + 24, dstIPv6, 16);

    pktLen = 40 + tcpLen;

    // --- TCP checksum (псевдозаголовок IPv6) ---
    {
        DWORD sum = 0;
        // Pseudo-header: src(16) + dst(16) + zero(1) + proto(1) + tcpLen(2)
        for (int i = 0; i < 16; i += 2) {
            sum += (DWORD)((srcIPv6[i] << 8) | srcIPv6[i + 1]);
            sum += (DWORD)((dstIPv6[i] << 8) | dstIPv6[i + 1]);
        }
        sum += 6;             // protocol TCP
        sum += tcpLen;
        // TCP segment
        for (DWORD i = 0; i < tcpLen; i += 2) {
            WORD w = (WORD)(tcp[i] << 8);
            if (i + 1 < tcpLen) w |= tcp[i + 1];
            sum += w;
        }
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        WORD cksum = (WORD)(~sum & 0xFFFF);
        tcp[16] = (BYTE)(cksum >> 8);
        tcp[17] = (BYTE)(cksum);
    }

    SendTraffic(peer, path, pktBuf, pktLen);
    outPacketLen = pktLen;
    return NULL;
}

// Find stream by destination port
int IronSession::FindStreamByPort(int port) const {
    for (int i = 0; i < MAX_VIRTUAL_STREAMS; i++) {
        if (m_streams[i].inUse && m_streams[i].sourcePort == port) {
            return i;
        }
    }
    return -1;
}

// Acquire a free virtual stream
int IronSession::AcquireStream() {
    EnterCriticalSection(&m_lock);
    DWORD now = GetTickCount();
    for (int i = 0; i < MAX_VIRTUAL_STREAMS; i++) {
        if (!m_streams[i].inUse) {
            // Монотонно возрастающий порт — никогда не совпадает с недавно использованным.
            LONG p = InterlockedExchangeAdd((LONG*)&s_nextPort, 7);
            int port = (int)(((p - 1025) % (65534 - 1025)) + 1025);
            m_streams[i].Reset(port);
            LeaveCriticalSection(&m_lock);
            WCHAR debug[256];
            wsprintf(debug, L"[STREAM] Acquired streamId=%d with port=%d", i, port);
            AddLog(debug, LOG_INFO);
            return i;
        }
    }
    // Все стримы заняты — принудительно освобождаем зависшие (inUse но без активности >30 сек)
    // Это защита от утечки стримов когда HTTP-поток упал не вызвав ReleaseStream
    for (int i = 0; i < MAX_VIRTUAL_STREAMS; i++) {
        if (m_streams[i].inUse) {
            DWORD idle = now - m_streams[i].sendWindowSize;  // используем как временную метку не лучший способ
            // Проверяем через recvQueue и tcpState: если TCP_CLOSED и очередь пуста — явная утечка
            bool leaked = (m_streams[i].tcpState == TCP_CLOSED &&
                           m_streams[i].recvQueue.empty() &&
                           m_streams[i].refCount <= 1);
            if (leaked) {
                WCHAR wdbg[128];
                wsprintf(wdbg, L"[STREAM] Force-releasing leaked streamId=%d", i);
                AddLog(wdbg, LOG_WARN);
                LONG p = InterlockedExchangeAdd((LONG*)&s_nextPort, 7);
                int port = (int)(((p - 1025) % (65534 - 1025)) + 1025);
                m_streams[i].Reset(port);
                LeaveCriticalSection(&m_lock);
                WCHAR debug[256];
                wsprintf(debug, L"[STREAM] Acquired (reclaimed) streamId=%d with port=%d", i, port);
                AddLog(debug, LOG_INFO);
                return i;
            }
        }
    }
    LeaveCriticalSection(&m_lock);
    AddLog(L"[STREAM] No free streams available!", LOG_ERROR);
    return -1;
}

// Release a virtual stream
void IronSession::ReleaseStream(int streamId) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return;
    EnterCriticalSection(&m_lock);
    m_streams[streamId].inUse = false;
    SetEvent(m_streams[streamId].recvEvent);
    LeaveCriticalSection(&m_lock);
}

void IronSession::ProcessIncomingTCP(IronPeer* peer, const vector<BYTE>& path, 
                                      const BYTE* ipv6Packet, DWORD len) {
    WCHAR debug[256];
    
    if (len < 40) return;
    
    int payloadLen = ((ipv6Packet[4] & 0xFF) << 8) | (ipv6Packet[5] & 0xFF);
    if (payloadLen < 20) return;
    
    int tcpStart = 40;
    
    // Extract source and destination ports
    WORD sPort = ((WORD)ipv6Packet[tcpStart] << 8) | ipv6Packet[tcpStart + 1];
    WORD dPort = ((WORD)ipv6Packet[tcpStart + 2] << 8) | ipv6Packet[tcpStart + 3];
    BYTE flags = ipv6Packet[tcpStart + 13];
    
    // Find stream by destination port
    int streamId = FindStreamByPort(dPort);
    
    wsprintf(debug, L"[TCP] Incoming: srcPort=%d dstPort=%d flags=0x%02x streamId=%d", 
             sPort, dPort, flags, streamId);
    AddLog(debug, LOG_DEBUG);
    
    if (streamId < 0) {
        // No stream found for this port - drop packet (stream already closed or invalid)
        return;  // Don't process - stream not found
    }
    
    DWORD seqNum = ((DWORD)ipv6Packet[tcpStart + 4] << 24) |
                   ((DWORD)ipv6Packet[tcpStart + 5] << 16) |
                   ((DWORD)ipv6Packet[tcpStart + 6] << 8) |
                   (DWORD)ipv6Packet[tcpStart + 7];
    DWORD ackNum = ((DWORD)ipv6Packet[tcpStart + 8] << 24) |
                   ((DWORD)ipv6Packet[tcpStart + 9] << 16) |
                   ((DWORD)ipv6Packet[tcpStart + 10] << 8) |
                   (DWORD)ipv6Packet[tcpStart + 11];
    
    // flags already extracted above for logging
    bool isFin = (flags & 0x01) != 0;
    bool isSyn = (flags & 0x02) != 0;
    bool isRst = (flags & 0x04) != 0;
    bool isAck = (flags & 0x10) != 0;
    
    int dataOffset = ((ipv6Packet[tcpStart + 12] & 0xF0) >> 4) * 4;
    int tcpPayloadLen = payloadLen - dataOffset;
    
    EnterCriticalSection(&m_lock);

    // Обработка SYN-ACK (только в состоянии SYN_SENT)
    if (m_streams[streamId].tcpState == TCP_SYN_SENT && isAck) {

        // Проверяем что ackNum соответствует нашему SYN — защита от запоздалых пакетов
        if (ackNum != m_streams[streamId].localSeq) {
            wsprintf(debug, L"[TCP] SYN_SENT: ackNum=%lu != localSeq=%lu, discarding stale packet", ackNum, m_streams[streamId].localSeq);
            AddLog(debug, LOG_WARN);
            LeaveCriticalSection(&m_lock);
            return;
        }

        m_streams[streamId].remoteSeq = seqNum;
        m_streams[streamId].nextExpectedSeq = (seqNum + (isSyn ? 1 : 0)) & 0xFFFFFFFF;
        if (m_streams[streamId].nextExpectedSeq == 0) m_streams[streamId].nextExpectedSeq = 1;

        m_streams[streamId].remoteAck = ackNum;
        m_streams[streamId].tcpState = TCP_ESTABLISHED;

        LeaveCriticalSection(&m_lock);
        SendACK(streamId, peer, path, m_streams[streamId].nextExpectedSeq);

        EnterCriticalSection(&m_lock);
        vector<BYTE> pending = m_streams[streamId].pendingData;
        m_streams[streamId].pendingData.clear();
        LeaveCriticalSection(&m_lock);

        if (pending.size() > 0) {
            SendData(streamId, peer, path, &pending[0], pending.size());
        }

        // Если в этом же пакете есть данные — обрабатываем их ниже
        if (tcpPayloadLen <= 0) return;
        EnterCriticalSection(&m_lock);
    }

    if (m_streams[streamId].tcpState != TCP_ESTABLISHED && m_streams[streamId].tcpState != TCP_FIN_WAIT) {
        LeaveCriticalSection(&m_lock);
        return;
    }
    
    // ACK в data-пакете — продвигаем send window
    if (isAck) {
        if (IsSeqGreater(ackNum, m_streams[streamId].sendUnacked)) {
            m_streams[streamId].sendUnacked = ackNum;
            WORD remoteWin = ((WORD)ipv6Packet[tcpStart + 14] << 8) | ipv6Packet[tcpStart + 15];
            if (remoteWin > 0) m_streams[streamId].sendWindowSize = remoteWin;
            SetEvent(m_streams[streamId].sendWindowEvent);
        }
    }

    // Обработка данных
    if (tcpPayloadLen > 0 && (tcpStart + dataOffset + tcpPayloadLen <= (int)len)) {
        const BYTE* payload = ipv6Packet + tcpStart + dataOffset;

        DWORD seqDiff = (seqNum - m_streams[streamId].nextExpectedSeq) & 0xFFFFFFFF;
        if (seqDiff > MAX_SEQ_JUMP && seqDiff < 0x80000000) {
            LeaveCriticalSection(&m_lock);
            return;
        }
        
        if (IsSeqGreater(m_streams[streamId].nextExpectedSeq, seqNum)) {
            DWORD expected = m_streams[streamId].nextExpectedSeq;
            LeaveCriticalSection(&m_lock);
            SendACK(streamId, peer, path, expected);
            return;
        }

        if (seqNum == m_streams[streamId].nextExpectedSeq) {
            DWORD nextSeq = (seqNum + tcpPayloadLen) & 0xFFFFFFFF;
            if (isSyn || isFin) nextSeq = (nextSeq + 1) & 0xFFFFFFFF;

            m_streams[streamId].nextExpectedSeq = nextSeq;
            m_streams[streamId].dupAckCount = 0;
            // Шлём ACK немедленно — до ProcessReassemblyBuffer.
            // При высоком RTT (700-1700ms) важно подтвердить как можно раньше,
            // иначе сервер уходит в retransmission и затем RST по RTO.
            DWORD immediateAck = nextSeq;
            LeaveCriticalSection(&m_lock);

            SendACK(streamId, peer, path, immediateAck);

            ProcessReassemblyBuffer(streamId, peer, path);

            DeliverToApplication(streamId, payload, tcpPayloadLen);
            
        } else if (IsSeqGreater(seqNum, m_streams[streamId].nextExpectedSeq)) {
            // Шлём dup-ACK на каждый out-of-order пакет без ограничения.
            // Это запускает fast retransmit на стороне сервера и убирает 6-секундный RTO-таймаут.
            m_streams[streamId].dupAckCount++;
            DWORD expected = m_streams[streamId].nextExpectedSeq;
            LeaveCriticalSection(&m_lock);
            SendDupACK(streamId, peer, path, expected);
            EnterCriticalSection(&m_lock);
            
            if (m_streams[streamId].reassemblyBufferSize + tcpPayloadLen <= MAX_REASSEMBLY_SIZE) {
                vector<BYTE> copy(payload, payload + tcpPayloadLen);
                m_streams[streamId].reassemblyBuffer[seqNum] = copy;
                if (m_streams[streamId].reassemblyBufferSize == 0) m_streams[streamId].oldestBufferedTime = GetTickCount();
                m_streams[streamId].reassemblyBufferSize += tcpPayloadLen;
            }
            LeaveCriticalSection(&m_lock);
            
        } else {
            DWORD overlap = m_streams[streamId].nextExpectedSeq - seqNum;
            if (overlap < (DWORD)tcpPayloadLen) {
                LeaveCriticalSection(&m_lock);
                DeliverToApplication(streamId, payload + overlap, tcpPayloadLen - overlap);
                EnterCriticalSection(&m_lock);
                m_streams[streamId].nextExpectedSeq = (seqNum + tcpPayloadLen) & 0xFFFFFFFF;
                LeaveCriticalSection(&m_lock);
                ProcessReassemblyBuffer(streamId, peer, path);
            } else {
                LeaveCriticalSection(&m_lock);
            }
        }
    } else {
        // Пакет без данных (только ACK или FIN)
        if (isAck) {
            m_streams[streamId].remoteAck = ackNum;
            if (IsSeqGreater(seqNum, m_streams[streamId].remoteSeq)) {
                m_streams[streamId].remoteSeq = seqNum;
            }
            // Продвигаем SND.UNA и обновляем размер окна
            if (IsSeqGreater(ackNum, m_streams[streamId].sendUnacked) ||
                ackNum == ((m_streams[streamId].sendUnacked + (m_streams[streamId].localSeq - m_streams[streamId].sendUnacked)) & 0xFFFFFFFF)) {
                m_streams[streamId].sendUnacked = ackNum;
            }
            // Window size из TCP заголовка (bytes 14-15)
            WORD remoteWin = ((WORD)ipv6Packet[tcpStart + 14] << 8) | ipv6Packet[tcpStart + 15];
            if (remoteWin > 0) m_streams[streamId].sendWindowSize = remoteWin;
            LeaveCriticalSection(&m_lock);
            SetEvent(m_streams[streamId].sendWindowEvent);
        } else {
            LeaveCriticalSection(&m_lock);
        }
    }
    
    // Обработка RST — сервер сбросил соединение на конкретном стриме
    if (isRst) {
        EnterCriticalSection(&m_lock);
        m_streams[streamId].tcpState = TCP_CLOSED;
        // Не трогаем m_bReady — RST относится только к этому TCP-соединению,
        // Ironwood-сессия остаётся валидной, другие стримы продолжают работу
        LeaveCriticalSection(&m_lock);
        AddLog(L"[TCP] RST received — connection reset by server", LOG_INFO);
        SetEvent(m_streams[streamId].sendWindowEvent);  // Разбудить SendData если ждёт окна
        NotifyDataReceived(streamId);  // Разбудить HTTP-поток чтобы он обнаружил закрытие
        return;
    }

    // Обработка FIN (выполняется вне блокировки данных)
    if (isFin) {
        EnterCriticalSection(&m_lock);
        // FIN принимаем только если он in-order (нет дырки перед ним).
        // Если seqNum > m_nextExpectedSeq — в reassembly буфере есть пропущенные данные,
        // FIN игнорируем: когда дырка закроется через ретрансмит — FIN придёт снова.
        bool finInOrder = !IsSeqGreater(seqNum, m_streams[streamId].nextExpectedSeq);
        if (finInOrder) {
            m_streams[streamId].serverFinReceived = true;
            m_streams[streamId].tcpState = TCP_FIN_WAIT;
            DWORD expectedAck = (seqNum + 1) & 0xFFFFFFFF;
            m_streams[streamId].nextExpectedSeq = expectedAck;
            LeaveCriticalSection(&m_lock);
            SetEvent(m_streams[streamId].sendWindowEvent);  // Разбудить SendData если ждёт окна
            NotifyDataReceived(streamId);  // Разбудить HTTP-поток
            SendACK(streamId, peer, path, expectedAck);
            // Не вызываем SendFIN здесь — HTTP-поток сам пошлёт FIN когда закончит отдавать данные
        } else {
            LeaveCriticalSection(&m_lock);
        }
    }
    
    CheckReassemblyTimeout(streamId, peer, const_cast<vector<BYTE>*>(&path));
}

void IronSession::ProcessReassemblyBuffer(int streamId, IronPeer* peer, const vector<BYTE>& path) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return;
    EnterCriticalSection(&m_lock);

    // Собираем все готовые сегменты в один список, сначала обновляем nextExpectedSeq
    vector<vector<BYTE> > toDeliver;

    while (!m_streams[streamId].reassemblyBuffer.empty()) {
        map<DWORD, vector<BYTE> >::iterator it = m_streams[streamId].reassemblyBuffer.begin();
        DWORD seq = it->first;

        if (seq == m_streams[streamId].nextExpectedSeq) {
            DWORD dataLen = (DWORD)it->second.size();
            m_streams[streamId].reassemblyBufferSize -= dataLen;
            m_streams[streamId].nextExpectedSeq = (seq + dataLen) & 0xFFFFFFFF;
            toDeliver.push_back(it->second);
            m_streams[streamId].reassemblyBuffer.erase(it);
        } else if (IsSeqGreater(seq, m_streams[streamId].nextExpectedSeq)) {
            break;  // Ждем предыдущих пакетов
        } else {
            // Пакет частично или полностью перекрывается с уже принятым (overlap).
            // Бывает после fast retransmit с другим MSS — удалять нельзя, нужно взять хвост.
            DWORD overlap = (m_streams[streamId].nextExpectedSeq - seq) & 0xFFFFFFFF;
            DWORD dataLen = (DWORD)it->second.size();
            if (overlap < dataLen) {
                // Есть новые данные после перекрытия — берём хвост
                vector<BYTE> tail(it->second.begin() + overlap, it->second.end());
                m_streams[streamId].reassemblyBufferSize -= dataLen;
                m_streams[streamId].reassemblyBuffer.erase(it);
                m_streams[streamId].nextExpectedSeq = (m_streams[streamId].nextExpectedSeq + (dataLen - overlap)) & 0xFFFFFFFF;
                toDeliver.push_back(tail);
            } else {
                // Полностью перекрыт — просто удаляем
                m_streams[streamId].reassemblyBufferSize -= dataLen;
                m_streams[streamId].reassemblyBuffer.erase(it);
            }
        }
    }

    if (m_streams[streamId].reassemblyBuffer.empty()) {
        m_streams[streamId].oldestBufferedTime = 0;
    }

    // Если reassembly продвинул nextExpectedSeq — шлём ACK немедленно, до deliver
    if (!toDeliver.empty()) {
        DWORD ackNow = m_streams[streamId].nextExpectedSeq;
        LeaveCriticalSection(&m_lock);
        SendACK(streamId, peer, path, ackNow);
        for (size_t i = 0; i < toDeliver.size(); i++) {
            DeliverToApplication(streamId, &toDeliver[i][0], (DWORD)toDeliver[i].size());
        }
    } else {
        LeaveCriticalSection(&m_lock);
    }
}

void IronSession::CheckReassemblyTimeout(int streamId, IronPeer* peer, vector<BYTE>* path) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return;
    EnterCriticalSection(&m_lock);

    if (m_streams[streamId].oldestBufferedTime != 0 &&
        (GetTickCount() - m_streams[streamId].oldestBufferedTime > REASSEMBLY_TIMEOUT)) {

        map<DWORD, vector<BYTE> >::iterator it = m_streams[streamId].reassemblyBuffer.begin();
        if (it != m_streams[streamId].reassemblyBuffer.end() && IsSeqGreater(it->first, m_streams[streamId].nextExpectedSeq)) {
            WCHAR debug[256];
            wsprintf(debug, L"[TCP] Reassembly timeout (expected %lu, got %lu), closing",
                     m_streams[streamId].nextExpectedSeq, it->first);
            AddLog(debug, LOG_ERROR);

            m_streams[streamId].reassemblyBuffer.clear();
            m_streams[streamId].reassemblyBufferSize = 0;
            m_streams[streamId].oldestBufferedTime = 0;
            m_streams[streamId].serverFinReceived = true;
            m_streams[streamId].tcpState = TCP_FIN_WAIT;
        }
    }

    // Периодически повторяем ACK чтобы сервер не сбросил соединение по таймауту.
    // Высокая задержка Yggdrasil (700-1700ms) приводит к потере ACK → сервер шлёт RST.
    // Повторяем каждые 2 секунды если соединение активно.
    bool shouldReAck = false;
    DWORD reAckSeq = 0;
    if (peer != NULL && path != NULL &&
        (m_streams[streamId].tcpState == TCP_ESTABLISHED || m_streams[streamId].tcpState == TCP_FIN_WAIT) &&
        m_streams[streamId].nextExpectedSeq != 0 &&
        (GetTickCount() - m_streams[streamId].delayedAckTime) > 2000) {
        m_streams[streamId].delayedAckTime = GetTickCount();
        reAckSeq = m_streams[streamId].nextExpectedSeq;
        shouldReAck = true;
    }

    LeaveCriticalSection(&m_lock);

    if (shouldReAck) {
        SendACK(streamId, peer, *path, reAckSeq);
    }

    NotifyDataReceived(streamId);
}

bool IronSession::IsSeqGreater(DWORD seq1, DWORD seq2) {
    DWORD diff = (seq1 - seq2) & 0xFFFFFFFF;
    return diff > 0 && diff < 0x80000000;
}

// Максимальный размер очереди приёма — 1MB на стрим.
// Увеличено с 256KB: Opera Mobile медленно читает, картинки >256KB обрезались при дропе.
#define RECV_QUEUE_MAX  (1024 * 1024)

void IronSession::DeliverToApplication(int streamId, const BYTE* data, DWORD len) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return;
    // Если установлен callback - вызываем его напрямую (legacy, only for stream 0)
    if (m_dataCallback && streamId == 0) {
        m_dataCallback(m_callbackContext, data, len);
        return;
    }

    // Защищаем доступ к очереди через m_lock (потокобезопасность)
    EnterCriticalSection(&m_lock);
    if (m_bClosed) { LeaveCriticalSection(&m_lock); return; }
    
    // Backpressure: если очередь слишком большая, дропаем данные
    DWORD sz = (DWORD)m_streams[streamId].recvQueue.size();
    DWORD off = m_streams[streamId].recvQueueOffset;
    DWORD queueUsed = (sz > off) ? (sz - off) : 0;
    
    if (queueUsed + len > RECV_QUEUE_MAX) {
        LeaveCriticalSection(&m_lock);
        AddLog(L"[TCP] recvQueue full, dropping data", LOG_WARN);
        return;
    }
    
    // Добавляем данные в очередь
    m_streams[streamId].recvQueue.insert(m_streams[streamId].recvQueue.end(), data, data + len);
    LeaveCriticalSection(&m_lock);
    
    // Сигнализируем о новых данных (вне блокировки)
    if (m_streams[streamId].recvEvent) SetEvent(m_streams[streamId].recvEvent);
}

void IronSession::SetDataCallback(DataCallback callback, void* context) {
    m_dataCallback = callback;
    m_callbackContext = context;
    AddLog(L"[SESSION] Data callback installed", LOG_DEBUG);
}

// ============================================================================
// UDP DNS (без TCP state machine)
// ============================================================================

bool IronSession::SendUdpDns(IronPeer* peer, const vector<BYTE>& path,
                              const BYTE* srcIPv6, const BYTE* dstIPv6,
                              WORD srcPort, const BYTE* dnsQuery, DWORD queryLen) {
    if (!m_bReady || m_bClosed) return false;

    WCHAR sendDbg[128];
    wsprintf(sendDbg, L"[UDP] Sending DNS query to port 53, srcPort=%d, queryLen=%lu", srcPort, (unsigned long)queryLen);
    AddLog(sendDbg, LOG_DEBUG);
    
    // DEBUG: адреса src и dst
    {
        WCHAR addrDbg[256];
        wsprintf(addrDbg, L"[UDP] Src: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            srcIPv6[0], srcIPv6[1], srcIPv6[2], srcIPv6[3],
            srcIPv6[4], srcIPv6[5], srcIPv6[6], srcIPv6[7],
            srcIPv6[8], srcIPv6[9], srcIPv6[10], srcIPv6[11],
            srcIPv6[12], srcIPv6[13], srcIPv6[14], srcIPv6[15]);
        AddLog(addrDbg, LOG_DEBUG);
        wsprintf(addrDbg, L"[UDP] Dst: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            dstIPv6[0], dstIPv6[1], dstIPv6[2], dstIPv6[3],
            dstIPv6[4], dstIPv6[5], dstIPv6[6], dstIPv6[7],
            dstIPv6[8], dstIPv6[9], dstIPv6[10], dstIPv6[11],
            dstIPv6[12], dstIPv6[13], dstIPv6[14], dstIPv6[15]);
        AddLog(addrDbg, LOG_DEBUG);
    }

    vector<BYTE> udpPkt = IPv6Packet::wrapUDP(srcIPv6, dstIPv6,
                                               srcPort, 53,
                                               dnsQuery, queryLen);
    if (udpPkt.empty()) return false;

    // DEBUG: HEX-дамп отправленного UDP пакета (IPv6 header + UDP header + DNS)
    {
        WCHAR hexDbg[256] = L"";
        int dumpLen = (udpPkt.size() < 64) ? (int)udpPkt.size() : 64;
        for(int i = 0; i < dumpLen; i++) {
            WCHAR b[4];
            wsprintf(b, L"%02x ", udpPkt[i]);
            wcscat(hexDbg, b);
        }
        WCHAR dbg[512];
        wsprintf(dbg, L"[UDP] Packet HEX (%d bytes): %s", (int)udpPkt.size(), hexDbg);
        AddLog(dbg, LOG_DEBUG);
    }

    // Очищаем старый ответ и флаги перед отправкой
    EnterCriticalSection(&m_lock);
    m_udpDnsResponse.clear();
    LeaveCriticalSection(&m_lock);
    m_udpDnsPortUnreachable = false;
    if (m_udpDnsEvent) ResetEvent(m_udpDnsEvent);

    return SendTraffic(peer, path, &udpPkt[0], (DWORD)udpPkt.size());
}

DWORD IronSession::ReadUdpDns(BYTE* buffer, DWORD maxLen, DWORD timeoutMs) {
    // Сначала проверяем без ожидания
    EnterCriticalSection(&m_lock);
    DWORD sz = (DWORD)m_udpDnsResponse.size();
    if (sz > 0) {
        DWORD toCopy = (sz < maxLen) ? sz : maxLen;
        memcpy(buffer, &m_udpDnsResponse[0], toCopy);
        m_udpDnsResponse.clear();
        LeaveCriticalSection(&m_lock);
        return toCopy;
    }
    LeaveCriticalSection(&m_lock);

    // Ждём события
    if (!m_udpDnsEvent) return 0;
    if (WaitForSingleObject(m_udpDnsEvent, timeoutMs) != WAIT_OBJECT_0) return 0;

    EnterCriticalSection(&m_lock);
    sz = (DWORD)m_udpDnsResponse.size();
    DWORD toCopy = (sz < maxLen) ? sz : maxLen;
    if (toCopy > 0) memcpy(buffer, &m_udpDnsResponse[0], toCopy);
    m_udpDnsResponse.clear();
    LeaveCriticalSection(&m_lock);
    return toCopy;
}

bool IronSession::ReadData(int streamId, BYTE* buffer, DWORD maxLen, DWORD& outLen, DWORD timeoutMs) {
    if (streamId < 0 || streamId >= MAX_VIRTUAL_STREAMS) return false;
    outLen = 0;

    // Проверяем очередь (с блокировкой для потокобезопасности)
    EnterCriticalSection(&m_lock);
    DWORD sz  = (DWORD)m_streams[streamId].recvQueue.size();
    DWORD off = m_streams[streamId].recvQueueOffset;
    // Защита от underflow: offset не может быть больше size после clear()
    if (off > sz) { m_streams[streamId].recvQueueOffset = 0; off = 0; }
    DWORD available = sz - off;
    if (available > 0) {
        DWORD toCopy = min(maxLen, available);
        memcpy(buffer, &m_streams[streamId].recvQueue[off], toCopy);
        m_streams[streamId].recvQueueOffset += toCopy;
        outLen = toCopy;
        if (m_streams[streamId].recvQueueOffset >= sz) {
            m_streams[streamId].recvQueue.clear();
            m_streams[streamId].recvQueueOffset = 0;
        }
        LeaveCriticalSection(&m_lock);
        return true;
    }
    LeaveCriticalSection(&m_lock);
    
    // Если callback установлен - чтение из очереди невозможно (only for stream 0)
    if (m_dataCallback && streamId == 0) {
        AddLog(L"[TCP] ReadData: callback installed, no data in queue", LOG_DEBUG);
        return false;
    }
    
    // Ждем данные
    if (m_streams[streamId].recvEvent) {
        DWORD result = WaitForSingleObject(m_streams[streamId].recvEvent, timeoutMs);
        if (result != WAIT_OBJECT_0) {
            return false;  // Таймаут или ошибка
        }
        
        // Повторяем попытку чтения (с блокировкой)
        EnterCriticalSection(&m_lock);
        DWORD sz2  = (DWORD)m_streams[streamId].recvQueue.size();
        DWORD off2 = m_streams[streamId].recvQueueOffset;
        if (off2 > sz2) { m_streams[streamId].recvQueueOffset = 0; off2 = 0; }
        DWORD avail2 = sz2 - off2;
        if (avail2 > 0) {
            DWORD toCopy = min(maxLen, avail2);
            memcpy(buffer, &m_streams[streamId].recvQueue[off2], toCopy);
            m_streams[streamId].recvQueueOffset += toCopy;
            outLen = toCopy;
            if (m_streams[streamId].recvQueueOffset >= sz2) {
                m_streams[streamId].recvQueue.clear();
                m_streams[streamId].recvQueueOffset = 0;
            }
            LeaveCriticalSection(&m_lock);
            return true;
        }
        LeaveCriticalSection(&m_lock);
    }
    
    return false;
}

bool IronSession::ReadData(BYTE* buffer, DWORD maxLen, DWORD& outLen, DWORD timeoutMs) {
    return ReadData(0, buffer, maxLen, outLen, timeoutMs);
}

void IronSession::NotifyDataReceived(int streamId) {
    if (streamId >= 0 && streamId < MAX_VIRTUAL_STREAMS && m_streams[streamId].recvEvent) {
        SetEvent(m_streams[streamId].recvEvent);
    }
}

void IronSession::NotifyDataReceived() {
    NotifyDataReceived(0);
}

int IronSession::GetActiveStreamCount() const {
    int count = 0;
    for (int i = 0; i < MAX_VIRTUAL_STREAMS; i++) {
        if (m_streams[i].inUse) count++;
    }
    return count;
}

