// YggConvert.h - Конвертация Ed25519 <-> X25519 ключей
#pragma once

#include "stdafx.h"

// Конвертация Ed25519 public key (32 bytes) -> X25519 public key (32 bytes)
// Ed25519 point: (x, y) in Edwards form
// X25519 point: u in Montgomery form
// Formula: u = (1 + y) / (1 - y) (mod 2^255-19)
bool Ed25519PubToX25519(const BYTE ed25519_pk[32], BYTE x25519_pk[32]);

// Конвертация Ed25519 private key (32 bytes seed) -> X25519 private key (32 bytes)
// Просто хешируем seed и модифицируем биты как для X25519
void Ed25519PrivToX25519(const BYTE ed25519_seed[32], BYTE x25519_sk[32]);
