// YggTypes.h - Общие типы и константы для Yggstack
#pragma once

#include "stdafx.h"
#include <windows.h>
#include <winsock2.h>
#include <vector>
#include <map>
#include <string>

using namespace std;

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

#ifndef KEY_SIZE
#define KEY_SIZE            32
#endif

#ifndef MAX_PEERS
#define MAX_PEERS           10
#endif

#define MAX_SESSIONS        32

// ============================================================================
// WIRE ПРОТОКОЛ - типы пакетов
// ============================================================================

#define WIRE_KEEP_ALIVE     0x01
#define WIRE_SIG_REQ        0x02
#define WIRE_SIG_RES        0x03
#define WIRE_ANNOUNCE       0x04
#define WIRE_BLOOM          0x05
#define WIRE_PATH_LOOKUP    0x06
#define WIRE_PATH_NOTIFY    0x07
#define WIRE_TRAFFIC        0x09

// ============================================================================
// ТИПЫ СЕССИЙ Ironwood
// ============================================================================

#define SESSION_INIT        0x01
#define SESSION_ACK         0x02
#define SESSION_TRAFFIC     0x03

// ============================================================================
// СТРУКТУРЫ
// ============================================================================

// Структура для хранения ключей
struct YggKeys {
    BYTE publicKey[KEY_SIZE];
    BYTE privateKey[KEY_SIZE * 2];  // 64 байта для Ed25519
    BYTE ipv6[16];
};

// ============================================================================
// ПРЕДВАРИТЕЛЬНЫЕ ОБЪЯВЛЕНИЯ КЛАССОВ
// ============================================================================

class IronPeer;
class IronSession;
class CYggdrasilCore;
