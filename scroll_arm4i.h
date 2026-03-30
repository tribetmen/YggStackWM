// scroll_arm4i.h - Библиотека прокрутки для ARM4i
// Оптимизировано для Windows Mobile 5/6

#ifndef SCROLL_ARM4I_H
#define SCROLL_ARM4I_H

#include <windows.h>

#define SCROLL_FPS              30
#define SCROLL_FRAME_MS         33
#define SCROLL_TIMER_ID         1001
#define SCROLL_FLING_DURATION   350
#define SCROLL_VELOCITY_THRESH  8
#define SCROLL_FLING_POWER      2
#define SCROLL_BOUNCE_FORCE      3

typedef enum {
    SCROLL_IDLE = 0,
    SCROLL_DRAGGING,
    SCROLL_FLINGING,
    SCROLL_BOUNCING
} ScrollMode;

typedef struct {
    int x, y;
    int minX, maxX;
    int minY, maxY;
    int dragX, dragY;
    int dragStartX, dragStartY;
    DWORD dragTime;
    int velX, velY;
    int flingX, flingY;
    DWORD flingTime;
    WORD flags;
    BYTE mode;
    HWND hWnd;
} ScrollState;

#define SCROLL_FLAG_X         0x0001
#define SCROLL_FLAG_Y         0x0002
#define SCROLL_FLAG_BOUNCE    0x0004

// Инициализация
static void Scroll_Init(ScrollState* s, HWND hWnd) {
    s->x = 0; s->y = 0;
    s->minX = 0; s->maxX = 0;
    s->minY = 0; s->maxY = 0;
    s->dragX = 0; s->dragY = 0;
    s->dragStartX = 0; s->dragStartY = 0;
    s->dragTime = 0;
    s->velX = 0; s->velY = 0;
    s->flingX = 0; s->flingY = 0;
    s->flingTime = 0;
    s->flags = SCROLL_FLAG_Y | SCROLL_FLAG_BOUNCE;
    s->mode = SCROLL_IDLE;
    s->hWnd = hWnd;
}

// Быстрая проверка границ
static int Scroll_Clamp(int pos, int min, int max, int bounce) {
    if (!bounce) {
        if (pos < min) return min;
        if (pos > max) return max;
        return pos;
    } else {
        if (pos < min) {
            return min - ((min - pos) / 2);
        }
        if (pos > max) {
            return max + ((pos - max) / 2);
        }
        return pos;
    }
}

// Принудительная фиксация позиции в границах
static void Scroll_ClampPosition(ScrollState* s) {
    int newX = Scroll_Clamp(s->x, s->minX, s->maxX, 0);
    int newY = Scroll_Clamp(s->y, s->minY, s->maxY, 0);
    
    if (newX != s->x || newY != s->y) {
        s->x = newX;
        s->y = newY;
        InvalidateRect(s->hWnd, NULL, FALSE);
    }
}

// Начало перетаскивания
static void Scroll_OnDragStart(ScrollState* s, int x, int y) {
    if (s->mode != SCROLL_IDLE) {
        KillTimer(s->hWnd, SCROLL_TIMER_ID);
    }
    
    s->dragX = x;
    s->dragY = y;
    s->dragStartX = s->x;
    s->dragStartY = s->y;
    s->dragTime = GetTickCount();
    s->mode = SCROLL_DRAGGING;
}

// Процесс перетаскивания
static void Scroll_OnDragMove(ScrollState* s, int x, int y) {
    if (s->mode != SCROLL_DRAGGING) return;
    
    int dx = (s->flags & SCROLL_FLAG_X) ? (x - s->dragX) : 0;
    int dy = (s->flags & SCROLL_FLAG_Y) ? (y - s->dragY) : 0;
    
    int bounce = (s->flags & SCROLL_FLAG_BOUNCE) ? 1 : 0;
    int newX = Scroll_Clamp(s->dragStartX - dx, s->minX, s->maxX, bounce);
    int newY = Scroll_Clamp(s->dragStartY - dy, s->minY, s->maxY, bounce);
    
    if (newX != s->x || newY != s->y) {
        s->x = newX;
        s->y = newY;
        InvalidateRect(s->hWnd, NULL, FALSE);
    }
}

// Вычисление скорости
static int Scroll_CalcVelocity(int delta, DWORD time) {
    if (time == 0) return 0;
    return (delta * 1000 / (int)time) / SCROLL_FLING_POWER;
}

// Завершение перетаскивания
static void Scroll_OnDragEnd(ScrollState* s) {
    if (s->mode != SCROLL_DRAGGING) return;
    
    DWORD dragTime = GetTickCount() - s->dragTime;
    
    if (dragTime < 200 && dragTime > 10) {
        int deltaX = s->x - s->dragStartX;
        int deltaY = s->y - s->dragStartY;
        
        s->velX = Scroll_CalcVelocity(deltaX, dragTime);
        s->velY = Scroll_CalcVelocity(deltaY, dragTime);
        
        if (s->velX > 400) s->velX = 400;
        if (s->velX < -400) s->velX = -400;
        if (s->velY > 400) s->velY = 400;
        if (s->velY < -400) s->velY = -400;
        
        if (abs(s->velX) > SCROLL_VELOCITY_THRESH || 
            abs(s->velY) > SCROLL_VELOCITY_THRESH) {
            
            s->flingX = s->x;
            s->flingY = s->y;
            s->flingTime = GetTickCount();
            s->mode = SCROLL_FLINGING;
            SetTimer(s->hWnd, SCROLL_TIMER_ID, SCROLL_FRAME_MS, NULL);
            return;
        }
    }
    
    Scroll_ClampPosition(s);
    s->mode = SCROLL_IDLE;
}

// Обновление инерции
static int Scroll_OnTimer(ScrollState* s) {
    if (s->mode != SCROLL_FLINGING) {
        KillTimer(s->hWnd, SCROLL_TIMER_ID);
        return 0;
    }
    
    DWORD now = GetTickCount();
    DWORD dt = now - s->flingTime;
    
    if (dt >= SCROLL_FLING_DURATION) {
        s->mode = SCROLL_IDLE;
        KillTimer(s->hWnd, SCROLL_TIMER_ID);
        Scroll_ClampPosition(s);
        return 1;
    }
    
    float progress = (float)dt / SCROLL_FLING_DURATION;
    
    int newX = s->flingX + (int)(s->velX * progress);
    int newY = s->flingY + (int)(s->velY * progress);
    
    int bounce = (s->flags & SCROLL_FLAG_BOUNCE) ? 1 : 0;
    newX = Scroll_Clamp(newX, s->minX, s->maxX, bounce);
    newY = Scroll_Clamp(newY, s->minY, s->maxY, bounce);
    
    if (newX != s->x || newY != s->y) {
        s->x = newX;
        s->y = newY;
        return 1;
    }
    
    return 0;
}

// Остановка
static void Scroll_Stop(ScrollState* s) {
    if (s->mode != SCROLL_IDLE) {
        KillTimer(s->hWnd, SCROLL_TIMER_ID);
        s->mode = SCROLL_IDLE;
        Scroll_ClampPosition(s);
    }
}

// Установка границ
static void Scroll_SetBounds(ScrollState* s, int minX, int maxX, int minY, int maxY) {
    s->minX = minX;
    s->maxX = maxX;
    s->minY = minY;
    s->maxY = maxY;
    Scroll_ClampPosition(s);
}

#endif // SCROLL_ARM4I_H