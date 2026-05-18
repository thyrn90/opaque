/*
 * =========================================================================================
 * OPAQUE - Zero-IAT Anti-Analysis & Custom VCPU Engine
 * Version: 2.1.0 (Open-Source Template)
 * Author: thyrn90
 * License: MIT
 * * Description:
 * A header-only, highly aggressive defense mechanism designed to detect and melt down 
 * debuggers, memory dumpers, and advanced ring-0 hooks. 
 * Features a Custom Bytecode VCPU, VM Fingerprinting, and Delayed Execution Chaos.
 * Operates entirely in the dark with Zero-IAT resolution and dynamic API hashing. 
 * * WARNING: 
 * This software performs low-level memory modifications, intentional access violations, 
 * and CPU locks. Use strictly for authorized security research and IP protection.
 * =========================================================================================
 */

#pragma once
#include <windows.h>
#include <intrin.h>

#define lIlI1I1 __forceinline

// [DEV] Change this XOR key (0x7381) to a unique hex value for your project
#define O0O0O0(x) (x ^ 0x7381) 

#define _THY_90_ __rdtsc()
#define l11ll1 CONTEXT
#define Il1I1I CONTEXT_DEBUG_REGISTERS

typedef BOOL (WINAPI *pVProt)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LPVOID (WINAPI *pVAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE (WINAPI *pCThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef PVOID (WINAPI *pAddVEH)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef ULONG (WINAPI *pRemVEH)(PVOID);
typedef BOOL (WINAPI *pGTC)(HANDLE, LPCONTEXT);
typedef UINT (WINAPI *pGSFT)(DWORD, DWORD, PVOID, DWORD);
typedef VOID (WINAPI *pSlp)(DWORD);

// [DEV] You can rename the namespace to something unique to avoid pattern matching
namespace _0xDEAD {

    lIlI1I1 void _M3M(void* d, int v, size_t l) {
        unsigned char* p = (unsigned char*)d;
        while (l--) *p++ = (unsigned char)v;
    }

   // --- FLAWLESS PEB WALKING ---
    lIlI1I1 void* _G37_M0D(char* enc, int len, char key) {
        char name[50];
        for(int i=0; i<len; i++) name[i] = enc[i] ^ key;
        
        unsigned char* peb = (unsigned char*)__readgsqword(0x60);
        unsigned char* ldr = *(unsigned char**)(peb + 0x18);
        unsigned char* head = ldr + 0x10; 
        unsigned char* curr = *(unsigned char**)head;
        
        void* res = nullptr;
        while (curr != head && curr != nullptr) {
            USHORT nameLen = *(USHORT*)(curr + 0x58); 
            
            if (nameLen == len * 2) { 
                wchar_t* wName = *(wchar_t**)(curr + 0x60); 
                if (wName) {
                    bool match = true;
                    for(int i=0; i<len; i++) {
                        char c = (char)wName[i];
                        if (c >= 'A' && c <= 'Z') c += 32;
                        char t = name[i];
                        if (t >= 'A' && t <= 'Z') t += 32;
                        if (c != t) { match = false; break; }
                    }
                    if (match) { 
                        res = *(void**)(curr + 0x30); 
                        break; 
                    } 
                }
            }
            curr = *(unsigned char**)curr;
        }
        _M3M(name, 0, 50); // Wipe resolved name from memory
        return res;
    }

    typedef FARPROC (WINAPI *pGPA)(HMODULE, LPCSTR);
    static pGPA myGetProcAddress = nullptr;

    lIlI1I1 void* _G37_FNC(void* mod, char* enc, int len, char key) {
        if (!mod) return nullptr;

        if (myGetProcAddress == nullptr) {
            // [DEV] String XOR Decryption: If you change the 'k' value, you MUST re-encrypt the byte arrays below!
            char k = 0x13;
            char s_k32[] = {(char)('k'^k), (char)('e'^k), (char)('r'^k), (char)('n'^k), (char)('e'^k), (char)('l'^k), (char)('3'^k), (char)('2'^k), (char)('.'^k), (char)('d'^k), (char)('l'^k), (char)('l'^k)};
            void* k32 = _G37_M0D(s_k32, 12, k); 

            if (k32) {
                unsigned char* base = (unsigned char*)k32;
                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
                PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

                DWORD* names = (DWORD*)(base + exp->AddressOfNames);
                DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
                WORD* ords = (WORD*)(base + exp->AddressOfNameOrdinals);

                for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                    char* exp_name = (char*)(base + names[i]);
                    if (exp_name[0]=='G' && exp_name[1]=='e' && exp_name[2]=='t' && exp_name[3]=='P' && exp_name[13]=='s') {
                        char target[] = "GetProcAddress";
                        bool isGPA = true;
                        for(int j=0; j<14; j++) if(exp_name[j] != target[j]) isGPA = false;
                        if(isGPA) {
                            myGetProcAddress = (pGPA)(base + funcs[ords[i]]);
                            break;
                        }
                    }
                }
            }
        }

        char name[50];
        for(int i=0; i<len; i++) name[i] = enc[i] ^ key;
        name[len] = '\0';

        void* res = nullptr;
        if (myGetProcAddress) {
            res = (void*)myGetProcAddress((HMODULE)mod, name);
        }

        _M3M(name, 0, 50); // Wipe resolved function name from memory
        return res;
    }

    // --- CORE PROTECTIONS ---
    lIlI1I1 bool _P3B() {
        #ifdef _WIN64
            unsigned char* p = (unsigned char*)__readgsqword(0x60);
            DWORD f = *(DWORD*)(p + 0xBC);
            return (p[2] == 1 || (f & 0x70) != 0);
        #else
            return false;
        #endif
    }

    lIlI1I1 bool _I1l1() {
        unsigned __int64 T1 = _THY_90_;
        volatile int OO00 = 0;
        for(int l1=0; l1<1000; l1++) { OO00 += (l1 ^ 0xABC); } 
        unsigned __int64 T2 = _THY_90_;
        // Adjusted threshold to prevent false positives on slower CPUs / power-saving modes
        return ((T2 - T1) > 0xFFFFFF); 
    }

    lIlI1I1 bool _O0O1() {
        // [DEV] Change 'k' (0x13) to your unique key and re-encrypt the strings
        char k = 0x13;
        char s_k32[] = {(char)('k'^k), (char)('e'^k), (char)('r'^k), (char)('n'^k), (char)('e'^k), (char)('l'^k), (char)('3'^k), (char)('2'^k), (char)('.'^k), (char)('d'^k), (char)('l'^k), (char)('l'^k)};
        char s_gtc[] = {(char)('G'^k), (char)('e'^k), (char)('t'^k), (char)('T'^k), (char)('h'^k), (char)('r'^k), (char)('e'^k), (char)('a'^k), (char)('d'^k), (char)('C'^k), (char)('o'^k), (char)('n'^k), (char)('t'^k), (char)('e'^k), (char)('x'^k), (char)('t'^k)};
        
        void* k32 = _G37_M0D(s_k32, 12, k);
        pGTC gtc = (pGTC)_G37_FNC(k32, s_gtc, 16, k);
        
        if (gtc) {
            l11ll1 O0;
            O0.ContextFlags = Il1I1I;
            if(gtc(((HANDLE)(LONG_PTR)-2), &O0)) {
                return (O0.Dr0 != 0 || O0.Dr1 != 0 || O0.Dr2 != 0 || O0.Dr3 != 0);
            }
        }
        return false;
    }

    lIlI1I1 bool _H00K() {
        // [DEV] Change 'k' (0x13) to your unique key and re-encrypt the strings
        char k = 0x13;
        char s_ntdll[] = {(char)('n'^k), (char)('t'^k), (char)('d'^k), (char)('l'^k), (char)('l'^k), (char)('.'^k), (char)('d'^k), (char)('l'^k), (char)('l'^k)};
        char s_f1[] = {(char)('N'^k), (char)('t'^k), (char)('Q'^k), (char)('u'^k), (char)('e'^k), (char)('r'^k), (char)('y'^k), (char)('I'^k), (char)('n'^k), (char)('f'^k), (char)('o'^k), (char)('r'^k), (char)('m'^k), (char)('a'^k), (char)('t'^k), (char)('i'^k), (char)('o'^k), (char)('n'^k), (char)('P'^k), (char)('r'^k), (char)('o'^k), (char)('c'^k), (char)('e'^k), (char)('s'^k), (char)('s'^k)};
        char s_f2[] = {(char)('N'^k), (char)('t'^k), (char)('S'^k), (char)('e'^k), (char)('t'^k), (char)('I'^k), (char)('n'^k), (char)('f'^k), (char)('o'^k), (char)('r'^k), (char)('m'^k), (char)('a'^k), (char)('t'^k), (char)('i'^k), (char)('o'^k), (char)('n'^k), (char)('T'^k), (char)('h'^k), (char)('r'^k), (char)('e'^k), (char)('a'^k), (char)('d'^k)};
        
        void* ntdll = _G37_M0D(s_ntdll, 9, k);
        if(ntdll) {
            void* f1 = _G37_FNC(ntdll, s_f1, 25, k);
            void* f2 = _G37_FNC(ntdll, s_f2, 22, k);
            void* arr[] = {f1, f2};
            
            for(int i = 0; i < 2; i++) {
                unsigned char* f = (unsigned char*)arr[i];
                if(f && (f[0] != 0x4C || f[1] != 0x8B || f[2] != 0xD1)) { return true; }
            }
        }
        return false;
    }

    static bool l11Il = false; 
    LONG WINAPI _V3H_H(PEXCEPTION_POINTERS ep) {
        if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
            l11Il = true; 
            ep->ContextRecord->Rip++; 
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    lIlI1I1 bool _V3H() {
        // [DEV] Change 'k' (0x13) to your unique key and re-encrypt the strings
        char k = 0x13;
        char s_k32[] = {(char)('k'^k), (char)('e'^k), (char)('r'^k), (char)('n'^k), (char)('e'^k), (char)('l'^k), (char)('3'^k), (char)('2'^k), (char)('.'^k), (char)('d'^k), (char)('l'^k), (char)('l'^k)};
        char s_av[] = {(char)('A'^k), (char)('d'^k), (char)('d'^k), (char)('V'^k), (char)('e'^k), (char)('c'^k), (char)('t'^k), (char)('o'^k), (char)('r'^k), (char)('e'^k), (char)('d'^k), (char)('E'^k), (char)('x'^k), (char)('c'^k), (char)('e'^k), (char)('p'^k), (char)('t'^k), (char)('i'^k), (char)('o'^k), (char)('n'^k), (char)('H'^k), (char)('a'^k), (char)('n'^k), (char)('d'^k), (char)('l'^k), (char)('e'^k), (char)('r'^k)};
        char s_rv[] = {(char)('R'^k), (char)('e'^k), (char)('m'^k), (char)('o'^k), (char)('v'^k), (char)('e'^k), (char)('V'^k), (char)('e'^k), (char)('c'^k), (char)('t'^k), (char)('o'^k), (char)('r'^k), (char)('e'^k), (char)('d'^k), (char)('E'^k), (char)('x'^k), (char)('c'^k), (char)('e'^k), (char)('p'^k), (char)('t'^k), (char)('i'^k), (char)('o'^k), (char)('n'^k), (char)('H'^k), (char)('a'^k), (char)('n'^k), (char)('d'^k), (char)('l'^k), (char)('e'^k), (char)('r'^k)};
        
        void* k32 = _G37_M0D(s_k32, 12, k);
        pAddVEH addveh = (pAddVEH)_G37_FNC(k32, s_av, 27, k);
        pRemVEH remveh = (pRemVEH)_G37_FNC(k32, s_rv, 30, k);
        
        if (addveh && remveh) {
            l11Il = false;
            PVOID h = addveh(1, _V3H_H);
            __debugbreak(); 
            remveh(h);
            return !l11Il; 
        }
        return false;
    }

    // --- SCORING SYSTEM ---
    lIlI1I1 int _VMM() {
        int score = 0;
        int CPUInfo[4] = {-1};
        __cpuid(CPUInfo, 1);
        
        // Hypervisor Bit check
        if ((CPUInfo[2] >> 31) & 1) {
            score += 20; 
            __cpuid(CPUInfo, 0x40000000);
            // Ignore standard Windows VBS/Hyper-V to avoid false positives for normal gamers
            bool is_windows_hv = (CPUInfo[1] == 0x7263694d && CPUInfo[2] == 0x666f736f && CPUInfo[3] == 0x76482074);
            if (!is_windows_hv) score += 40; // Heavy penalty for VMware, VBox, QEMU
        }
        return score;
    }

    // --- PAYLOADS ---
    lIlI1I1 void _K40S() {
        // [DEV] Change 'k' (0x13) to your unique key and re-encrypt the strings
        char k = 0x13;
        char s_k32[] = {(char)('k'^k), (char)('e'^k), (char)('r'^k), (char)('n'^k), (char)('e'^k), (char)('l'^k), (char)('3'^k), (char)('2'^k), (char)('.'^k), (char)('d'^k), (char)('l'^k), (char)('l'^k)};
        char s_va[] = {(char)('V'^k), (char)('i'^k), (char)('r'^k), (char)('t'^k), (char)('u'^k), (char)('a'^k), (char)('l'^k), (char)('A'^k), (char)('l'^k), (char)('l'^k), (char)('o'^k), (char)('c'^k)};
        char s_ct[] = {(char)('C'^k), (char)('r'^k), (char)('e'^k), (char)('a'^k), (char)('t'^k), (char)('e'^k), (char)('T'^k), (char)('h'^k), (char)('r'^k), (char)('e'^k), (char)('a'^k), (char)('d'^k)};
        
        void* k32 = _G37_M0D(s_k32, 12, k);
        pVAlloc va = (pVAlloc)_G37_FNC(k32, s_va, 12, k);
        pCThread ct = (pCThread)_G37_FNC(k32, s_ct, 12, k);
        
        // Decoy threads for analysis chaos
        if (ct) {
            for(int l1 = 0; l1 < 5; l1++) {
                ct(NULL, 0, [](LPVOID) -> DWORD {
                    volatile int OO00 = 0;
                    while(true) { OO00 += (OO00 * 0xABC) ^ 0x123; } 
                    return 0;
                }, NULL, 0, NULL);
            }
        }
        
        // The 500MB RAM bomb for Debuggers
        if (va) {
            void* O0 = va(NULL, 1024 * 1024 * 500, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (O0) { _M3M(O0, 0xCC, 1024 * 1024 * 500); }
        }
    }

    lIlI1I1 void _W1P3() {
        // [DEV] Change 'k' (0x13) to your unique key and re-encrypt the strings
        char k = 0x13;
        char s_k32[] = {(char)('k'^k), (char)('e'^k), (char)('r'^k), (char)('n'^k), (char)('e'^k), (char)('l'^k), (char)('3'^k), (char)('2'^k), (char)('.'^k), (char)('d'^k), (char)('l'^k), (char)('l'^k)};
        char s_vp[] = {(char)('V'^k), (char)('i'^k), (char)('r'^k), (char)('t'^k), (char)('u'^k), (char)('a'^k), (char)('l'^k), (char)('P'^k), (char)('r'^k), (char)('o'^k), (char)('t'^k), (char)('e'^k), (char)('c'^k), (char)('t'^k)};
        
        void* k32 = _G37_M0D(s_k32, 12, k);
        pVProt vp = (pVProt)_G37_FNC(k32, s_vp, 14, k);
        
        if (vp) {
            unsigned char* peb = (unsigned char*)__readgsqword(0x60);
            void* O0 = *(void**)(peb + 0x10);
            
            if (O0) {
                DWORD l1;
                if (vp(O0, 0x1000, PAGE_READWRITE, &l1)) {
                    _M3M(O0, 0, 0x200); // Wipe DOS/NT headers
                    vp(O0, 0x1000, l1, &l1);
                }
            }
        }
    }

    // --- OPAQUE VIRTUAL MACHINE (VCPU) ---
    
    DWORD WINAPI _V1RT_CPU(LPVOID lpParam) {
        
        // [DEV] Create your own unique Instruction Set Architecture (ISA)
        // Change the hex values to completely scramble the VCPU engine.
        enum _OPCODES { 
            OP_CHK_PEB = 0xAA, 
            OP_CHK_TME = 0xBB, 
            OP_CHK_CTX = 0xCC, 
            OP_CHK_HOK = 0xDD, 
            OP_CHK_VM  = 0xEE, 
            OP_CHK_VEH = 0xFF,
            OP_EVAL    = 0x11,
            OP_SLP     = 0x22,
            OP_END     = 0x99 
        };

        // [DEV] Shuffle this array sequence based on your new OPCODES above
        // Ensure OP_END remains at the logical conclusion.
        unsigned char _BYTECODE[] = { 
            OP_CHK_PEB, OP_CHK_TME, OP_CHK_CTX, OP_CHK_HOK, OP_CHK_VM, OP_CHK_VEH, OP_EVAL, OP_SLP, OP_END 
        };

        bool _DANGER = false;
        int _SCORE = 0;
        int _PC = 0; // Program Counter

        // [DEV] Change 'k' (0x13) to your unique key and re-encrypt the strings
        char k = 0x13;
        char s_k32[] = {(char)('k'^k), (char)('e'^k), (char)('r'^k), (char)('n'^k), (char)('e'^k), (char)('l'^k), (char)('3'^k), (char)('2'^k), (char)('.'^k), (char)('d'^k), (char)('l'^k), (char)('l'^k)};
        char s_slp[] = {(char)('S'^k), (char)('l'^k), (char)('e'^k), (char)('e'^k), (char)('p'^k)};
        void* k32 = _G37_M0D(s_k32, 12, k);
        pSlp slp = (pSlp)_G37_FNC(k32, s_slp, 5, k);

        while (true) {
            // Prevent false positive accumulation by resetting state at cycle start
            if (_PC == 0) {
                _SCORE = 0;
            }

            unsigned char op = _BYTECODE[_PC];
            
            // VCPU Dispatcher
            switch (op) {
                case OP_CHK_PEB: if(_P3B()) _DANGER = true; break;
                case OP_CHK_TME: if(_I1l1()) _DANGER = true; break;
                case OP_CHK_CTX: if(_O0O1()) _DANGER = true; break;
                case OP_CHK_HOK: if(_H00K()) _DANGER = true; break;
                case OP_CHK_VEH: if(_V3H()) _DANGER = true; break;
                case OP_CHK_VM:  _SCORE = _VMM(); break; // Overwrite, do not accumulate
                
                case OP_EVAL:
                    if (_SCORE >= 70 || _DANGER) {
                        // Delayed Execution Chaos: Wait before exploding to confuse analysts
                        if (slp) slp(2000 + (_THY_90_ % 3000)); 
                        _K40S(); 
                        volatile int* lIl = nullptr; *lIl = O0O0O0(0xDEAD); // Force Access Violation
                    } else {
                        _W1P3(); // Wipe headers if clean
                    }
                    break;
                
                case OP_SLP:
                    if (slp) slp(1000); // Sleep to reduce CPU load
                    _PC = -1; // Reset Program Counter
                    break;

                case OP_END:
                    return 0; 
            }
            _PC++;
        }
        return 0;
    }

    lIlI1I1 void RUN_OPAQUE() {
        // [DEV] Change 'k' (0x13) to your unique key and re-encrypt the strings
        char k = 0x13;
        char s_k32[] = {(char)('k'^k), (char)('e'^k), (char)('r'^k), (char)('n'^k), (char)('e'^k), (char)('l'^k), (char)('3'^k), (char)('2'^k), (char)('.'^k), (char)('d'^k), (char)('l'^k), (char)('l'^k)};
        char s_ct[] = {(char)('C'^k), (char)('r'^k), (char)('e'^k), (char)('a'^k), (char)('t'^k), (char)('e'^k), (char)('T'^k), (char)('h'^k), (char)('r'^k), (char)('e'^k), (char)('a'^k), (char)('d'^k)};
        
        void* k32 = _G37_M0D(s_k32, 12, k);
        pCThread ct = (pCThread)_G37_FNC(k32, s_ct, 12, k);
        
        if (ct) {
            // Spawn VCPU as a detached background thread (Ghost Thread)
            HANDLE hThread = ct(NULL, 0, _V1RT_CPU, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);
        } else {
            // Fallback if CreateThread fails
            _V1RT_CPU(NULL); 
        }
    }
}

#define OPAQUE_INIT() _0xDEAD::RUN_OPAQUE()