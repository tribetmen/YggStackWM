// randombytes_win32.c
#include <windows.h>
#include <wincrypt.h>

/* Кешируем провайдер — CryptAcquireContext грузит rsaenh.dll каждый раз */
static HCRYPTPROV s_hProv = 0;

static HCRYPTPROV GetCachedProvider(void) {
    if (s_hProv != 0) return s_hProv;
    if (!CryptAcquireContext(&s_hProv, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        s_hProv = 0;
    }
    return s_hProv;
}

void randombytes(unsigned char *x, unsigned long long xlen) {
    unsigned long long i;
    HCRYPTPROV hProv = GetCachedProvider();
    if (!hProv) {
        for (i = 0; i < xlen; i++) x[i] = 0;
        return;
    }
    CryptGenRandom(hProv, (DWORD)xlen, x);
}