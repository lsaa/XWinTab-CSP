//
// This is Windows code that provides the wintab API to the application.
// Currently only the parts needed by Rebelle are implemented. If no device is
// found, it will still offer a context, because Rebelle will reconfigure and
// persist the user settings to not use wintab otherwise.
//

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlobj.h>
#include <windows.h>

#include "wintab.h"
#include "XWinTabTypes.h"

typedef void (WINAPI *EventCallback)(EventInfo *);

typedef struct PacketDataTAG {
    UINT pkStatus;
    DWORD pkTime;
    DWORD pkChanged;
    UINT pkSerialNumber;
    DWORD pkButtons;
    LONG pkX;
    LONG pkY;
    UINT pkNormalPressure;
    ORIENTATION pkOrientation;
} PacketData;

typedef struct PacketQueueTAG {
    PacketData *buffer;
    int count;
    int size;
    int nextWrite;
    int nextRead;
} PacketQueue;

typedef struct ContextTAG {
    PacketQueue queue;
    HWND hwnd;
    HCTX handle;
    BOOL enabled;
    BOOL inProximity;
    LOGCONTEXTW logContext;
} Context;


static BOOL g_didInit;
static Context g_context;
static DeviceInfo g_deviceInfo;

static CRITICAL_SECTION g_lock;
static HMODULE g_module;
static HANDLE g_thread;
static BOOL g_threadStop;

static int (WINAPI *pLoad)(void);
static DeviceInfo* (WINAPI *pGetSelectedDevice)();
static int (WINAPI *pBeginEvents)(EventCallback callback);
static int (WINAPI *pCheckEvents)(int timeout);
static int (WINAPI *pShutdown)(void);

#define XWT_PACKET        0
#define XWT_CTXOPEN       1
#define XWT_CTXCLOSE      2
#define XWT_CTXOVERLAP    4
#define XWT_PROXIMITY     5

#define XWINTAB_VERSION_STRINGIFY(S) #S
#define XWINTAB_VERSION_MAJOR 0
#define XWINTAB_VERSION_MINOR 2
#define XWINTAB_NAME(MA,MI) "XWinTab " XWINTAB_VERSION_STRINGIFY(MA) "." \
                                       XWINTAB_VERSION_STRINGIFY(MI)

static const char kXWinTabID[] = XWINTAB_NAME(XWINTAB_VERSION_MAJOR,
                                              XWINTAB_VERSION_MINOR);

static FILE *g_logFile;


// ----------------
// Logging
//

void err_dlg(const WCHAR *msg) {
    MessageBoxW(NULL, msg, L"XWinTab Error", MB_OK);
}

static void init_log() {
    WCHAR wbuffer[MAX_PATH];

    DWORD result = GetEnvironmentVariableW(L"XWINTAB_LOG", wbuffer, MAX_PATH);
    if (!result || result >= MAX_PATH)
        return;

    if (wbuffer[0] != '1' || wbuffer[1] != 0)
        return;

    if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, wbuffer))) {
        err_dlg(L"Error getting user folder for log file");
        return;
    }

    const WCHAR suffix[] = L"\\XWinTabLog.txt";
    size_t path_len = wcslen(wbuffer);

    if ((MAX_PATH - sizeof(suffix)) < path_len) {
        err_dlg(L"Error opening log file: path length too big.");
        return;
    }

    for (int i = 0; i < sizeof(suffix); i++)
        wbuffer[path_len + i] = suffix[i];

    g_logFile = _wfopen(wbuffer, L"wb");
    if (!g_logFile)
        err_dlg(L"Error opening log file: _wfopen() failed.");
}

static void log_str(const char *str) {
    if (!g_logFile)
        return;
    fprintf(g_logFile, "%s", str);
}

static void log_strf(const char *fmt, ...) {
    if (!g_logFile)
        return;
    va_list args;
    va_start(args, fmt);
    vfprintf(g_logFile, fmt, args);
    va_end(args);
}

static void close_log() {
    if (!g_logFile)
        return;
    fclose(g_logFile);
    g_logFile = NULL;
}


// ----------------
// Packet Queue
//

static BOOL queue_init(PacketQueue *queue) {
    queue->buffer = (PacketData *) malloc(sizeof(PacketData) * 2048);

    if (!queue->buffer)
        return FALSE;

    queue->count = 0;
    queue->size = 2048;
    queue->nextRead = 0;
    queue->nextWrite = 0;

    return TRUE;
}

static PacketData* queue_read(PacketQueue *queue) {
    if (!queue->count)
        return NULL;
    PacketData *result = queue->buffer + queue->nextRead;
    queue->count--;
    queue->nextRead = (queue->nextRead + 1) % queue->size;
    return result;
}

static PacketData* queue_peek_prev(PacketQueue *queue) {
    if (!queue->count)
        return NULL;
    if (queue->count == 1)
        return queue->buffer + queue->nextRead;

    int idx = queue->nextWrite ? queue->nextWrite : queue->size;
    return queue->buffer + idx - 1;
}

typedef BOOL (*QueueItrFunc)(PacketData *, void *);

static void queue_iterate(PacketQueue *queue, QueueItrFunc fn, void *userData) {
    if (!queue->count || !fn)
        return;

    int pos = queue->nextRead;
    for (int i = 0; i < queue->count; i++) {
        if (!fn(queue->buffer + pos, userData))
            break;
        pos = (pos + 1) % queue->size;
    }
}

static PacketData* queue_write(PacketQueue *queue) {
    if (queue->count == queue->size)
        return NULL;
    PacketData *result = queue->buffer + queue->nextWrite;
    queue->count++;
    queue->nextWrite = (queue->nextWrite + 1) % queue->size;
    return result;
}

static BOOL queue_resize(PacketQueue *queue, int size) {
    if (size < 1)
        return FALSE;

    if (size == queue->size)
        return TRUE;

    PacketData *resized = (PacketData *) malloc(sizeof(PacketData) * size);
    if (!resized)
        return FALSE;

    if (!queue->count) {
        free(queue->buffer);
        queue->buffer = resized;
        queue->size = size;
        queue->nextRead = 0;
        queue->nextWrite = 0;
        return TRUE;
    }

    int copied = 0;
    int new_count = queue->count > size ? size : queue->count;
    int n = queue->size - queue->nextRead;

    if (n > new_count)
        n = new_count;

    memcpy(resized, &queue->buffer[queue->nextRead], n * sizeof(PacketData));
    copied = n;

    if (copied != new_count) {
        n = new_count - copied;
        // Correctly copy the number of bytes for the wrapped-around portion
        memcpy(&resized[copied], queue->buffer, n * sizeof(PacketData));
    }

    free(queue->buffer);
    queue->buffer = resized;
    queue->size = size;
    queue->count = new_count;
    queue->nextRead = 0;
    queue->nextWrite = new_count == size ? 0 : new_count;
    return TRUE;
}

static void queue_free(PacketQueue *queue) {
    if (queue->buffer)
        free(queue->buffer);
    queue->buffer = NULL;
    queue->size = 0;
    queue->count = 0;
}


// ----------------
// Event Handling
//

static BOOL context_message(Context *ctx, UINT msg, WPARAM wParam,
                            LPARAM lParam) {
    BOOL result;
    result = PostMessageW(ctx->hwnd, msg + ctx->logContext.lcMsgBase,
                          wParam, lParam);
    if (!result)
        log_strf("context_message send fail\n");
    return result;
}

static UINT copy_field(void *dst, const void *src, size_t size) {
    UINT size32 = (UINT) size;

    const char *ps = (const char *) src;
    char *pd = (char *) dst;

    for (UINT i = 0; i < size32; i++)
        pd[i] = ps[i];

    return size32;
}

static UINT packet_copy(Context *ctx, const PacketData *packet, void *out) {
    UINT written = 0;
    char *pkt = (char *) out;
    WTPKT mask = ctx->logContext.lcPktData;

    if (mask & PK_CONTEXT)
        written += copy_field(&pkt[written], &ctx->handle, sizeof(HCTX));
    if (mask & PK_STATUS)
        written += copy_field(&pkt[written], &packet->pkStatus, sizeof(UINT));
    if (mask & PK_TIME)
        written += copy_field(&pkt[written], &packet->pkTime, sizeof(LONG));
    if (mask & PK_CHANGED)
        written += copy_field(&pkt[written], &packet->pkChanged, sizeof(WTPKT));
    if (mask & PK_SERIAL_NUMBER)
        written += copy_field(&pkt[written], &packet->pkSerialNumber,
                              sizeof(UINT));
    if (mask & PK_CURSOR) {
        UINT data = 1;
        written += copy_field(&pkt[written], &data, sizeof(UINT));
    }
    if (mask & PK_BUTTONS)
        written += copy_field(&pkt[written], &packet->pkButtons, sizeof(DWORD));
    if (mask & PK_X)
        written += copy_field(&pkt[written], &packet->pkX, sizeof(LONG));
    if (mask & PK_Y)
        written += copy_field(&pkt[written], &packet->pkY, sizeof(LONG));
    if (mask & PK_Z) {
        LONG data = 0;
        written += copy_field(&pkt[written], &data, sizeof(LONG));
    }
    if (mask & PK_NORMAL_PRESSURE)
        written += copy_field(&pkt[written], &packet->pkNormalPressure,
                              sizeof(UINT));
    if (mask & PK_TANGENT_PRESSURE) {
        // Unsupported
        UINT data = 0;
        written += copy_field(&pkt[written], &data, sizeof(UINT));
    }
    if (mask & PK_ORIENTATION)
        written += copy_field(&pkt[written], &packet->pkOrientation,
                              sizeof(ORIENTATION));
    if (mask & PK_ROTATION) {
        // Unsupported
        ROTATION data;
        data.roPitch = data.roRoll = data.roYaw = 0;
        written += copy_field(&pkt[written], &data, sizeof(ROTATION));
    }
    log_strf("packet: x %d y %d p %d serial %d\n",
            packet->pkX, packet->pkY, packet->pkNormalPressure, packet->pkSerialNumber);
    return written;
}

static LONG scale_axis(LONG in, LONG inOrg, LONG inExt, LONG outOrg,
                       LONG outExt) {
    if ((inExt > 0 && outExt > 0) || (inExt < 0 && outExt < 0))
        return MulDiv(in - inOrg, abs(outExt), abs(inExt)) + outOrg;

    return MulDiv(abs(inExt) - (in - inOrg), abs(outExt), abs(inExt)) + outOrg;
}

static int calculate_azimuth(int x, int y) {
    double angle = atan2(-x, y) + M_PI;
    int result = 0.5 + (angle * 1800.0 / M_PI);
    return result < 3600 ? result : 0;
}

static void WINAPI on_event(EventInfo *ev) {
    static UINT serial = 0;

    EnterCriticalSection(&g_lock);

    if (ev->type == kEventTypeMotionNotify
        && ev->pressure == 0
        && g_context.inProximity)
    {
        g_context.inProximity = FALSE;
        // send WT_PROXIMITY(FALSE)
        context_message(&g_context,
                        XWT_PROXIMITY,
                        (WPARAM)g_context.handle,
                        MAKELPARAM(FALSE, 1));
        LeaveCriticalSection(&g_lock);
        return;
    }

    BOOL is_proximity = ev->type == kEventTypeProximityIn ||
                        ev->type == kEventTypeProximityOut;

    // Sometimes the stylus may already be in proximity by the time we are
    // loaded and some drivers don't emit proximity events at all.
    if (g_deviceInfo.id != -1 && !g_context.inProximity && !is_proximity) {
        log_strf("on_event: Converting normal event to proximity event\n");
        ev->type = kEventTypeProximityIn;
        is_proximity = TRUE;
    }

    if (!g_context.enabled && (!is_proximity || g_deviceInfo.id == -1)) {
        log_strf("on_event: rejecting %d\n", ev->type);
        LeaveCriticalSection(&g_lock);
        return;
    }

    PacketData *pkt = queue_write(&g_context.queue);
    if (!pkt) {
        log_strf("on_event: Queue Full\n");
        // Queue totally full. Last pkt as overflowed.
        pkt = queue_peek_prev(&g_context.queue);
        pkt->pkStatus |= TPS_QUEUE_ERR;
        LeaveCriticalSection(&g_lock);
        return;
    }

    // Extra bump if we wrapped around
    if (!serial)
        serial++;

    memset(pkt, 0, sizeof(PacketData));

    // Set proximity status
    if (ev->type == kEventTypeProximityIn) {
        g_context.inProximity = TRUE;
        pkt->pkStatus |= TPS_PROXIMITY;
    }
    else if (ev->type == kEventTypeProximityOut)
        g_context.inProximity = FALSE;
    else if (g_context.inProximity)
        pkt->pkStatus |= TPS_PROXIMITY;

    // Does this actually need adjusted?
    pkt->pkTime = ev->time;

    pkt->pkSerialNumber = serial++;
    pkt->pkButtons = ev->buttonsState;

    const LOGCONTEXTW *lc = &g_context.logContext;
    pkt->pkX = scale_axis(ev->x, lc->lcInOrgX, lc->lcInExtX, lc->lcOutOrgX,
                          lc->lcOutExtX);

    LONG fy = lc->lcInExtY - ev->y;
    pkt->pkY = scale_axis(fy, lc->lcInOrgY, lc->lcInExtY, lc->lcOutOrgY,
                          lc->lcOutExtY);

    pkt->pkNormalPressure = ev->pressure;

    pkt->pkOrientation.orAltitude = 900 - 15 * max(abs(ev->xTilt),
                                                   abs(ev->yTilt));

    pkt->pkOrientation.orAzimuth = calculate_azimuth(ev->xTilt, ev->yTilt);

    // Can't be bothered computing this properly right now.
    pkt->pkChanged = g_context.logContext.lcPktData;

    log_strf("event: x %d y %d p %d tltx %d tlty %d serial %d\n",
            ev->x, ev->y, ev->pressure, ev->xTilt, ev->yTilt, pkt->pkSerialNumber);

    if (ev->type == kEventTypeProximityIn ||
        ev->type == kEventTypeProximityOut) {
        BOOL isIn = ev->type == kEventTypeProximityIn;
        log_strf("on_event: Send WT_PROXIMITY %d\n", isIn);
        context_message(&g_context, XWT_PROXIMITY, (WPARAM) g_context.handle,
                        MAKELPARAM(isIn, 1));
    }
    else if (g_context.logContext.lcOptions & CXO_MESSAGES) {
        log_strf("on_event: Send WT_PACKET\n");
        context_message(&g_context, XWT_PACKET, pkt->pkSerialNumber,
                        (LPARAM) g_context.handle);
    }

    LeaveCriticalSection(&g_lock);
}

static DWORD WINAPI thread_func(void *userdata) {
    while (!g_threadStop) {
        if (!pCheckEvents(100))
            return -1;
    }
    return 0;
}


// ----------------
// Connection and Context Setup
//

static BOOL load_xwintab() {
    WCHAR wbuffer[MAX_PATH];
    DWORD result = GetEnvironmentVariableW(L"LOADED_MESSAGE", wbuffer, MAX_PATH);
    if (result)
        err_dlg(L"XWinTab-CSP was injected successfully!");

    InitializeCriticalSection(&g_lock);
    g_deviceInfo.id = -1;
    g_didInit = TRUE;
    g_module = LoadLibraryW(L"XWinTabHelper.dll.so");
    if (!g_module) {
        log_strf("Failed to load XWinTabHelper.dll.so\n");
        return FALSE;
    }

    log_strf("Loaded XWinTabHelper.dll.so\n");

    pLoad = (void*) GetProcAddress(g_module, "Load");
    pGetSelectedDevice = (void*) GetProcAddress(g_module, "GetSelectedDevice");
    pBeginEvents = (void*) GetProcAddress(g_module, "BeginEvents");
    pCheckEvents = (void*) GetProcAddress(g_module, "CheckEvents");
    pShutdown = (void*) GetProcAddress(g_module, "Shutdown");

    if (pLoad && pGetSelectedDevice && pBeginEvents && pCheckEvents && pShutdown) {
        log_strf("Loaded funcs\n");

        if (pLoad()) {
            log_strf("Load() call succeeded\n");
            DeviceInfo *device = pGetSelectedDevice();
            if (device) {
                g_deviceInfo = *device;
                log_strf("Using device: %d\n", g_deviceInfo.id);
                return TRUE;
            }
            g_deviceInfo.id = -1;
            log_strf("Couldn't find suitable tablet device\n");
        }
        else
            log_strf("Load() call failed\n");

        pShutdown();
    }
    else
        log_strf("Failed to load funcs\n");

    FreeLibrary(g_module);
    g_module = NULL;
    return FALSE;
}

static void init_log_context(LPLOGCONTEXTW lctx) {
    memset(lctx, 0, sizeof(LOGCONTEXTW));

    for (size_t i = 0; i < sizeof(kXWinTabID); i++)
        lctx->lcName[i] = kXWinTabID[i];

    lctx->lcOptions = CXO_SYSTEM;
    lctx->lcStatus = CXS_ONTOP;
    lctx->lcLocks = CXL_INSIZE | CXL_INASPECT | CXL_MARGIN |
                    CXL_SENSITIVITY | CXL_SYSOUT;
    lctx->lcMsgBase = WT_DEFBASE;
    lctx->lcDevice = 0;
    lctx->lcPktRate = 100;
    lctx->lcPktData = PK_CONTEXT | PK_STATUS | PK_SERIAL_NUMBER| PK_TIME |
                      PK_CURSOR | PK_BUTTONS |  PK_X | PK_Y |
                      PK_NORMAL_PRESSURE | PK_ORIENTATION;
    lctx->lcPktMode = 0;
    lctx->lcMoveMask = PK_BUTTONS | PK_X | PK_Y | PK_NORMAL_PRESSURE |
                       PK_ORIENTATION;
    lctx->lcBtnDnMask = 0xffffffff;
    lctx->lcBtnUpMask = 0xffffffff;

    lctx->lcInOrgZ = lctx->lcInExtZ = lctx->lcOutOrgZ = lctx->lcOutExtZ = 0;

    if (g_deviceInfo.id == -1) {
        // Didn't detect a plugged in tablet so just set some dummy values.
        lctx->lcInOrgX = lctx->lcInOrgY = 0;
        lctx->lcInExtX = lctx->lcInExtY = 1024;
    } else {
        lctx->lcInOrgX = g_deviceInfo.xAxis.min;
        lctx->lcInOrgY = g_deviceInfo.yAxis.min;
        lctx->lcInExtX = g_deviceInfo.xAxis.max - g_deviceInfo.xAxis.min;
        lctx->lcInExtY = g_deviceInfo.yAxis.max - g_deviceInfo.yAxis.min;
    }

    lctx->lcSensX = 65536;
    lctx->lcSensY = 65536;
    lctx->lcSensZ = 65536;
    lctx->lcSysMode = 0;

    lctx->lcSysOrgX = lctx->lcOutOrgX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    lctx->lcSysOrgY = lctx->lcOutOrgY = GetSystemMetrics(SM_YVIRTUALSCREEN);
    lctx->lcSysExtX = lctx->lcOutExtX = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    lctx->lcSysExtY = lctx->lcOutExtY = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    lctx->lcSysSensX = 65536;
    lctx->lcSysSensY = 65536;
}


// ----------------
// API Definitions
//

HCTX WINAPI WTOpenW(HWND hwnd, LPLOGCONTEXTW pLContext, BOOL enable) {
    if (!g_didInit)
        load_xwintab();
    if (g_context.handle || !pLContext)
        return NULL;

    if (!pLContext->lcInExtX || !pLContext->lcInExtY)
        return NULL;


    log_strf("WTOpenW: Begin context creation\n");
    g_context.handle = (HCTX) 128;
    g_context.logContext = *pLContext;
    g_context.hwnd = hwnd;

    if (g_deviceInfo.id != -1) {
        g_context.enabled = enable;
        g_context.logContext.lcStatus = enable ? CXS_ONTOP : CXS_DISABLED;

        if (!queue_init(&g_context.queue)) {
            g_deviceInfo.id = -1;
            return NULL;
        }

        // We want to hold off on the thread sending events
        EnterCriticalSection(&g_lock);

        if (!pBeginEvents(on_event)) {
            log_strf("WTOpenW: Failed to select events\n");
            g_context.enabled = FALSE;
            g_deviceInfo.id = -1;
            LeaveCriticalSection(&g_lock);
            pShutdown();
            return NULL;
        }

        g_thread = CreateThread(NULL, 0, thread_func, NULL, 0, NULL);
        if (!g_thread) {
            log_strf("WTOpenW: Failed to start event thread\n");
            g_context.enabled = FALSE;
            g_deviceInfo.id = -1;
            LeaveCriticalSection(&g_lock);
            pShutdown();
            return NULL;
        }

        log_strf("WTOpenW: Started Event Thread\n");
    }

    context_message(&g_context, XWT_CTXOPEN, (WPARAM) g_context.handle,
                    g_context.logContext.lcStatus);

    context_message(&g_context, XWT_CTXOVERLAP, (WPARAM) g_context.handle,
                    g_context.logContext.lcStatus);

    // We can let the event thread do its thing now.
    if (g_deviceInfo.id != -1)
        LeaveCriticalSection(&g_lock);

    return g_context.handle;
}

BOOL WINAPI WTClose(HCTX ctx) {
    if (!ctx || g_context.handle != ctx)
        return FALSE;

    if (g_deviceInfo.id != -1) {
        g_threadStop = TRUE;
        WaitForSingleObject(g_thread, INFINITE);
        g_thread = NULL;
        g_threadStop = FALSE;
        queue_free(&g_context.queue);    
        g_context.handle   = 0;         
        g_context.inProximity = FALSE;   
        pShutdown();
        g_deviceInfo.id = -1;
        g_context.enabled = FALSE;
    }
    context_message(&g_context, XWT_CTXCLOSE, (WPARAM) g_context.handle,
                    g_context.logContext.lcStatus);
    return TRUE;
}

UINT WINAPI WTInfoW(UINT cat, UINT idx, LPVOID ptr) {
    if (!g_didInit)
        load_xwintab();

    if ((cat == WTI_DEVICES || cat == 0) && idx == 0) {
        log_strf("WTInfoW: Answering request for device X/Y axis info (cat: %u, idx: %u)\n", cat, idx);
        if (ptr) {
            LPAXIS out = (LPAXIS) ptr;
            if (g_deviceInfo.id != -1) {
                out[0].axMin = g_deviceInfo.xAxis.min;
                out[0].axMax = g_deviceInfo.xAxis.max;
                out[0].axResolution = g_deviceInfo.xAxis.resolution;
                out[0].axUnits = TU_INCHES;

                out[1].axMin = g_deviceInfo.yAxis.min;
                out[1].axMax = g_deviceInfo.yAxis.max;
                out[1].axResolution = g_deviceInfo.yAxis.resolution;
                out[1].axUnits = TU_INCHES;
            } else {
                out[0].axMin = 0;
                out[0].axMax = 1024;
                out[0].axResolution = 1;
                out[0].axUnits = TU_INCHES;

                out[1].axMin = 0;
                out[1].axMax = 1024;
                out[1].axResolution = 1;
                out[1].axUnits = TU_INCHES;
            }
        }
        return sizeof(AXIS) * 2;
    }


    if (cat == WTI_DEVICES && idx == 1) {
        log_strf("WTInfoW: Reporting Y axis min=%d, max=%d\n",
             g_deviceInfo.id != -1 ? g_deviceInfo.yAxis.min : 0,
             g_deviceInfo.id != -1 ? g_deviceInfo.yAxis.max : 1024);
        if (ptr) {
            LPAXIS out = (LPAXIS) ptr;
            if (g_deviceInfo.id != -1) {
                out->axMin        = g_deviceInfo.yAxis.min;
                out->axMax        = g_deviceInfo.yAxis.max;
                out->axResolution = g_deviceInfo.yAxis.resolution;
            } else {
                out->axMin        = 0;
                out->axMax        = 1024;
                out->axResolution = 1;
            }
            out->axUnits = TU_INCHES;
        }
        return sizeof(AXIS);
    }

    if ((cat == WTI_DEFCONTEXT || cat == WTI_DEFSYSCTX) && !idx) {
        log_strf("WTInfoW: Request for default logcontext\n");
        if (ptr)
            init_log_context((LPLOGCONTEXTW) ptr);
        return sizeof(LOGCONTEXTW);
    }

    if (cat == WTI_DEVICES && idx == DVC_ORIENTATION) {
        if (ptr) {
            LPAXIS out = (LPAXIS) ptr;
            out[0].axMin = 0;
            out[0].axMax = 3600;
            out[0].axUnits = TU_CIRCLE;
            out[0].axResolution = CASTFIX32(3600);

            out[1].axMin = -900;//-1000;
            out[1].axMax = 900;//1000;
            out[1].axUnits = TU_CIRCLE;
            out[1].axResolution = CASTFIX32(3600);

            out[2].axMin = 0;
            out[2].axMax = 3600;
            out[2].axUnits = TU_CIRCLE;
            out[2].axResolution = CASTFIX32(3600);
        }
        return sizeof(AXIS) * 3;
    }

    if (cat == WTI_DEVICES && idx == DVC_NPRESSURE) {
        log_strf("WTInfoW: Reporting pressure axis min=%d, max=%d\n",
             g_deviceInfo.id != -1 ? g_deviceInfo.pressureAxis.min : 0,
             g_deviceInfo.id != -1 ? g_deviceInfo.pressureAxis.max : 1024);
        if (ptr) {
            LPAXIS out = (LPAXIS) ptr;
            if (g_deviceInfo.id != -1) {
                out->axMin = g_deviceInfo.pressureAxis.min;
                out->axMax = g_deviceInfo.pressureAxis.max;
                out->axResolution = g_deviceInfo.pressureAxis.resolution;
            } else {
                out->axMin = 0;
                out->axMax = 1024;
                out->axResolution = 1;
            }
            out->axUnits = TU_INCHES;
        }
        return sizeof(AXIS);
    }

    if (cat == WTI_DEVICES && idx == DVC_TPRESSURE) {
        if (ptr) {
            // Unsupported
            LPAXIS out = (LPAXIS) ptr;
            out->axMin = 0;
            out->axMax = 0;
            out->axResolution = 0;
            out->axUnits = TU_INCHES;
        }
        return sizeof(AXIS);
    }

    if (cat == (WTI_CURSORS + 1) && idx == CSR_PHYSID) {
        if (ptr) {
            LPDWORD out = (LPDWORD) ptr;
            *out = 0;
        }
        return sizeof(DWORD);
    }

    if (cat == (WTI_CURSORS + 1) && idx == CSR_TYPE) {
        if (ptr) {
            LPUINT out = (LPUINT) ptr;
            *out = 0x822;
        }
        return sizeof(UINT);
    }

    if (cat == (WTI_CURSORS + 1) && idx == CSR_SYSBTNMAP) {
        if (ptr) {
            memset(ptr, 0, sizeof(BYTE)*32);
            LPBYTE out = (LPBYTE) ptr;
            for (int i = 0; i < 8; i++)
                out[i] = 1 << i;
        }
        return sizeof(BYTE) * 32;
    }

    if (cat == WTI_INTERFACE) {
        if (idx == IFC_WINTABID) {
            if (ptr) {
                wchar_t *out = (wchar_t *) ptr;
                for (size_t i = 0; i < sizeof(kXWinTabID); i++)
                    out[i] = kXWinTabID[i];
            }
            return sizeof(kXWinTabID) * sizeof(wchar_t);
        }

        if (idx == IFC_IMPLVERSION) {
            if (ptr) {
                WORD *out = (WORD *) ptr;
                *out = (XWINTAB_VERSION_MAJOR << 8) | XWINTAB_VERSION_MINOR;
            }
            return sizeof(WORD);
        }
    }

    log_strf("WTInfow: unhandled cat %d idx %d\n", cat, idx);
    return 0;
}

BOOL WINAPI WTEnable(HCTX ctx, BOOL enable) {
    if (!ctx || g_context.handle != ctx)
        return FALSE;
    // We won't be getting any events anyway
    if (g_deviceInfo.id == -1)
        return TRUE;

    EnterCriticalSection(&g_lock);
    g_context.enabled = enable;
    log_strf("WTEnable: %d\n", enable);
    LeaveCriticalSection(&g_lock);

    g_context.logContext.lcStatus = enable ? CXS_ONTOP : CXS_DISABLED;

    context_message(&g_context, XWT_CTXOVERLAP, (WPARAM) g_context.handle,
                    g_context.logContext.lcStatus);
    return TRUE;
}

BOOL WINAPI WTOverlap(HCTX ctx, BOOL top) {
    // Stub, there's only one context.
    log_strf("WTOverlap: %d\n", top);
    return (!ctx || g_context.handle != ctx) ? FALSE : TRUE;
}

int WINAPI WTPacketsGet(HCTX ctx, int count, LPVOID ptr) {
    log_strf("WTPacketsGet: %d\n", count);
    if (!ctx || g_context.handle != ctx)
        return 0;
    if (count < 1)
        return 0;
    EnterCriticalSection(&g_lock);
    int read = 0;
    char *out = (char *) ptr;
    while (read != count) {
        PacketData *pkt = queue_read(&g_context.queue);
        if (!pkt)
            break;
        log_strf("WTPacketsGet read a packet\n", read);
        if (out)
            out += packet_copy(&g_context, pkt, out);
        read++;
    }
    log_strf("WTPacketsGet Read: %d Packets\n", read);
    LeaveCriticalSection(&g_lock);
    return read;
}

typedef struct PktPeekIterData {
    int read;
    int count;
    char *dst;
} PktPeekIterData;


static BOOL pkt_peek_itr(PacketData *pkt, void *userData) {
    // Correctly cast the incoming userData pointer
    PktPeekIterData *data = (PktPeekIterData *) userData;

    // Now that 'data' is valid, the rest of the function works correctly
    if (data->dst) {
        data->dst += packet_copy(&g_context, pkt, data->dst);
    }
    data->read++;

    return data->read < data->count;
}

int WINAPI WTPacketsPeek(HCTX ctx, int count, LPVOID ptr) {
    if (!ctx || g_context.handle != ctx)
        return 0;
    if (count < 1)
        return 0;
    EnterCriticalSection(&g_lock);

    PktPeekIterData data;
    data.read = 0;
    data.count = count;
    data.dst = (char *) ptr;

    queue_iterate(&g_context.queue, pkt_peek_itr, &data);

    LeaveCriticalSection(&g_lock);
    return data.read;
}

BOOL WINAPI WTGetW(HCTX ctx, LPLOGCONTEXTW pLContext) {
    if (!ctx || g_context.handle != ctx || !pLContext)
        return FALSE;
    *pLContext = g_context.logContext;
    return TRUE;
}

int WINAPI WTQueueSizeGet(HCTX ctx) {
    log_strf("WTQueueSizeGet: %d\n", ctx && g_context.handle == ctx);
    if (!ctx || g_context.handle != ctx)
        return 0;
    return g_context.queue.size;
}

BOOL WINAPI WTQueueSizeSet(HCTX ctx, int size) {
    log_strf("WTQueueSizeSet: %d\n", size);
    if (!ctx || g_context.handle != ctx || !size)
        return FALSE;
    if (size == g_context.queue.size)
        return TRUE;

    EnterCriticalSection(&g_lock);
    BOOL result = queue_resize(&g_context.queue, size);
    LeaveCriticalSection(&g_lock);
    return result;
}

// BOOL APIENTRY DllMain(HMODULE hModule, DWORD  reason, LPVOID lpReserved) {
//     if (reason == DLL_PROCESS_DETACH) {
//         close_log();
//         return TRUE;
//     }
//     if (reason == DLL_PROCESS_ATTACH) {
//         init_log();
//         return TRUE;
//     }
//     return FALSE;
// }
//
//

// Helper to find a packet by serial in the queue (must be called under g_lock)
static PacketData* find_packet_by_serial(PacketQueue *queue, UINT serial) {
    if (!queue->count)
        return NULL;

    int pos = queue->nextRead;
    for (int i = 0; i < queue->count; i++) {
        PacketData *pkt = &queue->buffer[pos];
        if (pkt->pkSerialNumber == serial)
            return pkt;
        pos = (pos + 1) % queue->size;
    }
    return NULL;
}

BOOL WINAPI WTPacket(HCTX ctx, UINT serial, LPVOID pktOut) {
    if (!ctx || g_context.handle != ctx)
        return FALSE;

    EnterCriticalSection(&g_lock);

    BOOL found = FALSE;
    int packets_to_consume = 0;

    // Stage 1: Search for the packet without modifying the queue.
    if (g_context.queue.count > 0) {
        int search_pos = g_context.queue.nextRead;
        for (int i = 0; i < g_context.queue.count; i++) {
            packets_to_consume++;
            PacketData *pkt = &g_context.queue.buffer[search_pos];

            if (pkt->pkSerialNumber == serial) {
                found = TRUE;
                if (pktOut) {
                    packet_copy(&g_context, pkt, pktOut);
                }
                break;
            }
            search_pos = (search_pos + 1) % g_context.queue.size;
        }
    }

    // Stage 2: If found, consume all packets up to and including the target.
    // If not found, the queue remains untouched.
    if (found) {
        for (int i = 0; i < packets_to_consume; i++) {
            // This simply advances the read pointer and decrements the count.
            queue_read(&g_context.queue);
        }
    }

    LeaveCriticalSection(&g_lock);
    return found;
}

BOOL WINAPI WTQueuePacketsEx(HCTX ctx, UINT *pBegin, UINT *pEnd) {
    if (!ctx || g_context.handle != ctx || !pBegin || !pEnd)
        return FALSE;

    EnterCriticalSection(&g_lock);

    if (g_context.queue.count == 0) {
        *pBegin = *pEnd = 0;
    } else {
        PacketData *first = &g_context.queue.buffer[g_context.queue.nextRead];
        int lastIdx = (g_context.queue.nextWrite + g_context.queue.size - 1)
                      % g_context.queue.size;
        PacketData *last = &g_context.queue.buffer[lastIdx];

        *pBegin = first->pkSerialNumber;
        *pEnd   = last->pkSerialNumber;
    }

    LeaveCriticalSection(&g_lock);
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            init_log();
            log_str("DllMain: DLL_PROCESS_ATTACH received.\n");
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            log_str("DllMain: DLL_PROCESS_DETACH received.\n");
            close_log();
            break;
    }
    return TRUE; // Always return TRUE from DllMain
}
