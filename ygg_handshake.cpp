// ygg_handshake.cpp - ������� ��������
#include "stdafx.h"
#include "ygg_handshake.h"

extern "C" {
#include "blake2.h"
#include "tweetnacl32.h"
}

extern void AddLog(LPCWSTR text, BYTE type);

// === �����������: ����� Ed25519 ������� ��� ���������� ��������� ===

// TweetNaCl crypto_sign ��������� message � signature.
// ��� ����� ��������� ������ (���� 64 ����), ��� message.
// �� ������ ����� ������������ ����!

// Ed25519 private key � TweetNaCl: 64 ����
// [0..31] - seed (������ ����)
// [32..63] - public key (���)

static void prepare_ed25519_secret_key(unsigned char *sk, 
                                        const unsigned char *seed,
                                        const unsigned char *pk) {
    // ���������� 64-������ secret key: seed + pk
    memcpy(sk, seed, 32);
    memcpy(sk + 32, pk, 32);
}

BOOL PerformHandshake(SOCKET sock, const BYTE* ourPubKey, const BYTE* ourPrivKey, 
                      BYTE* peerPubKey, DWORD* peerPort, const BYTE* password) {
    
    WCHAR debug[256];
    AddLog(L"[HS] Starting handshake...", 0);
    
    // === 1. TLV (53 ����) ===
    BYTE tlv[53];
    int pos = 0;
    
    tlv[pos++] = 0x00; tlv[pos++] = 0x00;
    tlv[pos++] = 0x00; tlv[pos++] = 0x02;
    tlv[pos++] = 0x00; tlv[pos++] = 0x00;
    
    tlv[pos++] = 0x00; tlv[pos++] = 0x01;
    tlv[pos++] = 0x00; tlv[pos++] = 0x02;
    tlv[pos++] = 0x00; tlv[pos++] = 0x05;
    
    tlv[pos++] = 0x00; tlv[pos++] = 0x02;
    tlv[pos++] = 0x00; tlv[pos++] = 0x20;
    memcpy(tlv + pos, ourPubKey, 32);
    pos += 32;
    
    tlv[pos++] = 0x00; tlv[pos++] = 0x03;
    tlv[pos++] = 0x00; tlv[pos++] = 0x01;
    tlv[pos++] = 0x00;
    
    // === 2. BLAKE2B ���� ===
    BYTE hashToSign[64];
    blake2b_state S;
    
    DWORD passLen = (password != NULL) ? strlen((const char*)password) : 0;
    
    int blakeRes;
    if(passLen > 0) {
        BYTE keyBuffer[64] = {0};
        memcpy(keyBuffer, password, (passLen > 64) ? 64 : passLen);
        blakeRes = blake2b_init_key(&S, 64, keyBuffer, (passLen > 64) ? 64 : passLen);
    } else {
        blakeRes = blake2b_init(&S, 64);
    }
    
    if(blakeRes != 0) {
        AddLog(L"[HS] ERROR: blake2b init failed!", 2);
        return FALSE;
    }
    
    blake2b_update(&S, ourPubKey, 32);
    blake2b_final(&S, hashToSign, 64);
    
    WCHAR hashStr[100];
    hashStr[0] = 0;
    for(int i = 0; i < 16; i++) wsprintf(hashStr + wcslen(hashStr), L"%02x", hashToSign[i]);
    wsprintf(debug, L"[HS] Hash: %s...", hashStr);
    AddLog(debug, 0);
    
    // === 3. ������� ED25519 ===
    // �������� 64-������ secret key: seed (32) + pubkey (32)
    BYTE expandedSk[64];
    
    // ourPrivKey ������ ����� 32 ��� 64 ����
    // ���� 64 ���� - ���� ���� 32 ��� seed
    // ���� 32 ���� - �� ��� seed
    memcpy(expandedSk, ourPrivKey, 32);  // seed
    
    // ���������� public key �� ������ ��������
    memcpy(expandedSk + 32, ourPubKey, 32);
    
    // ������������ � ������ TweetNaCl crypto_sign
    // ���������: [64 bytes signature][64 bytes message] = 128 bytes
    BYTE signedMsg[128];  // 64 sig + 64 msg
    unsigned int signedLen = 0;
    
    DWORD signStart = GetTickCount();
    int signRes = crypto_sign(signedMsg, &signedLen, hashToSign, 64, expandedSk);
    DWORD signTime = GetTickCount() - signStart;
    
    wsprintf(debug, L"[HS] Sign result: %d, len: %llu, time=%lums", signRes, signedLen, signTime);
    AddLog(debug, signRes == 0 ? 0 : 2);
    
    if(signRes != 0 || signedLen != 128) {
        AddLog(L"[HS] ERROR: signing failed!", 2);
        return FALSE;
    }
    
    // ���������� ������ ������� (���� 64 ����)
    BYTE signature[64];
    memcpy(signature, signedMsg, 64);
    
    // Self-verify ������ 4 ������� �� ARM! �������� ��� �������� �������
    // #ifdef DEBUG_SELF_VERIFY
    // BYTE verifyBuf[64];
    // unsigned int verifyLen;
    // int verifyRes = crypto_sign_open(verifyBuf, &verifyLen, signedMsg, signedLen, ourPubKey);
    // wsprintf(debug, L"[HS] Self-verify: %d", verifyRes);
    // AddLog(debug, verifyRes == 0 ? 4 : 2);
    // #endif
    
    // === 4. �������� ===
    BYTE packet[123];
    int p = 0;
    
    memcpy(packet + p, "meta", 4); p += 4;
    packet[p++] = 0x00; packet[p++] = 0x75;  // 117 = 0x0075 BE
    memcpy(packet + p, tlv, 53); p += 53;
    memcpy(packet + p, signature, 64); p += 64;
    
    int sent = send(sock, (char*)packet, p, 0);
    if(sent != p) {
        AddLog(L"[HS] ERROR: send failed!", 2);
        return FALSE;
    }
    
    // === 5. �������� ������ ===
    BYTE respMagic[4];
    int received = recv(sock, (char*)respMagic, 4, 0);
    
    if(received != 4 || memcmp(respMagic, "meta", 4) != 0) {
        AddLog(L"[HS] ERROR: no valid response!", 2);
        return FALSE;
    }
    
    BYTE respLenBuf[2];
    recv(sock, (char*)respLenBuf, 2, 0);
    WORD respLen = ((WORD)respLenBuf[0] << 8) | respLenBuf[1];
    
    if(respLen > 2048) return FALSE;
    
    BYTE* respData = new BYTE[respLen];
    received = recv(sock, (char*)respData, respLen, 0);
    
    if(received != respLen) {
        delete[] respData;
        return FALSE;
    }
    
    // ���� ������� ����
    BOOL found = FALSE;
    for(int i = 0; i <= (int)respLen - 36; i++) {
        WORD type = ((WORD)respData[i] << 8) | respData[i+1];
        WORD len = ((WORD)respData[i+2] << 8) | respData[i+3];
        if(type == 2 && len == 32 && (i + 36) <= respLen) {
            memcpy(peerPubKey, respData + i + 4, 32);
            found = TRUE;
            break;
        }
    }
    
    delete[] respData;
    
    if(found) {
        AddLog(L"[HS] SUCCESS!", 4);
    } else {
        AddLog(L"[HS] peer key not found", 2);
    }
    
    return found;
}
