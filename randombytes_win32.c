// randombytes_win32.c
#include <windows.h>
#include <wincrypt.h>

void randombytes(unsigned char *x, unsigned long long xlen) {
    HCRYPTPROV hProv = 0;
    unsigned long long i;  // Объявляем ВСЕ переменные в начале
    
    // Получаем криптографический провайдер
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        // Если не получилось - заполняем нулями (плохо, но не падаем)
        for (i = 0; i < xlen; i++) x[i] = 0;
        return;
    }
    
    // Генерируем случайные байты
    CryptGenRandom(hProv, (DWORD)xlen, x);
    
    // Освобождаем провайдер
    CryptReleaseContext(hProv, 0);
}