// stdafx.h : âêëþ÷àåìûé ôàéë äëÿ ñòàíäàðòíûõ ñèñòåìíûõ âêëþ÷àåìûõ ôàéëîâ
//

#pragma once

// Îïðåäåëåíèÿ áàçîâûõ òèïîâ äëÿ âñåé ïðîãðàììû
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

// Windows Header Files:
#include <windows.h>
#include <commctrl.h>
#include <aygshell.h>
#include <ctype.h>  // Для isxdigit, iswxdigit

// Äëÿ Windows Mobile
#include <shellapi.h>

// Äëÿ Winsock
#include <winsock2.h>
#include <ws2tcpip.h>

// Äëÿ ðàáîòû ñ Unicode
#ifndef _UNICODE
#define _UNICODE
#endif

#ifndef UNICODE
#define UNICODE
#endif

// Îòêëþ÷àåì ïðåäóïðåæäåíèÿ î íåáåçîïàñíûõ ôóíêöèÿõ
#pragma warning(disable: 4996)

// Ññûëêè íà áèáëèîòåêè
#pragma comment(lib, "commctrl.lib")
#pragma comment(lib, "aygshell.lib")
#pragma comment(lib, "ws2.lib")  // Äîáàâèòü äëÿ ñîêåòîâ
#pragma comment(lib, "crypt32.lib")  // Äîáàâèòü äëÿ CryptAPI

// Îïðåäåëåíèÿ äëÿ êðèïòîãðàôèè
#ifndef _CRT_RAND_S
#define _CRT_RAND_S
#endif

// Ìàêñèìàëüíûå ðàçìåðû
#define MAX_LOG_LINES 500
#define MAX_PEERS 20

// Îïðåäåëåíèå IDI_APPLICATION äëÿ Windows Mobile
#ifndef IDI_APPLICATION
#define IDI_APPLICATION MAKEINTRESOURCE(32512)
#endif

// Äîïîëíèòåëüíûå îïðåäåëåíèÿ äëÿ Windows Mobile
#define TCS_FIXEDWIDTH 0x0400

#ifdef __cplusplus
extern "C" {
#endif

// TweetNaCl functions are now declared in tweetnacl32.h
// Include tweetnacl32.h instead of duplicating declarations here

#ifdef __cplusplus
}
#endif

// Äëÿ ðàáîòû ñ òàáàìè
#ifndef WC_TABCONTROL
#define WC_TABCONTROL L"SysTabControl32"
#endif