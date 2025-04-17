#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <chrono>
#include <winhttp.h>
#include "ThemidaSDK.h"
#pragma comment(lib, "winhttp.lib")

bool enb() {
    HANDLE h;
    TOKEN_PRIVILEGES t;
    LUID l;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h)) return 0;
    if (!LookupPrivilegeValueA(0, SE_DEBUG_NAME, &l)) {
        CloseHandle(h);
        return 0;
    }
    t.PrivilegeCount = 1;
    t.Privileges[0].Luid = l;
    t.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(h, 0, &t, sizeof(t), 0, 0)) {
        CloseHandle(h);
        return 0;
    }
    CloseHandle(h);
    return 1;
}

DWORD pid(const std::wstring& n) {
    DWORD p = 0;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W e;
    e.dwSize = sizeof(e);
    if (Process32FirstW(h, &e)) {
        do {
            if (n == e.szExeFile) {
                p = e.th32ProcessID;
                break;
            }
        } while (Process32NextW(h, &e));
    }
    CloseHandle(h);
    return p;
}

struct C {
    DWORD p;
    std::wstring t;
    bool s;
};

BOOL CALLBACK ewp(HWND h, LPARAM l) {
    C* d = (C*)l;
    DWORD w;
    GetWindowThreadProcessId(h, &w);
    if (w == d->p && IsWindowVisible(h)) {
        if (SetWindowTextW(h, d->t.c_str()))
            d->s = 1;
    }
    return 1;
}

bool cwt(DWORD p, const std::wstring& t) {
    C d = { p, t, 0 };
    EnumWindows(ewp, (LPARAM)&d);
    return d.s;
}

void sg() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}

void rc() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void ap(const std::wstring& t, int d = 30) {
    for (wchar_t c : t) {
        std::wcout << c << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(d));
    }
    std::wcout << std::endl;
}

struct A {
    uintptr_t a;
    unsigned char b;
};

struct P {
    std::wstring p;
    std::string m;
    std::vector<A> t;
};

uintptr_t gba(DWORD p, const char* m) {
    uintptr_t b = 0;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p);
    if (h == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 e;
    e.dwSize = sizeof(e);
    if (Module32First(h, &e)) {
        do {
            if (_stricmp(e.szModule, m) == 0) {
                b = (uintptr_t)e.modBaseAddr;
                break;
            }
        } while (Module32Next(h, &e));
    }
    CloseHandle(h);
    return b;
}

std::wstring dfc(const std::wstring& u) {
    URL_COMPONENTS c;
    ZeroMemory(&c, sizeof(c));
    c.dwStructSize = sizeof(c);
    wchar_t h[256], p[1024];
    c.lpszHostName = h;
    c.dwHostNameLength = sizeof(h) / sizeof(wchar_t);
    c.lpszUrlPath = p;
    c.dwUrlPathLength = sizeof(p) / sizeof(wchar_t);
    if (!WinHttpCrackUrl(u.c_str(), u.length(), 0, &c)) return L"";

    HINTERNET s = WinHttpOpen(L"PF", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 0, 0, 0);
    if (!s) return L"";

    HINTERNET cn = WinHttpConnect(s, c.lpszHostName, c.nPort, 0);
    if (!cn) {
        WinHttpCloseHandle(s);
        return L"";
    }

    HINTERNET r = WinHttpOpenRequest(cn, L"GET", c.lpszUrlPath, 0, 0, 0,
        (c.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!r || !WinHttpSendRequest(r, 0, 0, 0, 0, 0, 0) || !WinHttpReceiveResponse(r, 0)) {
        if (r) WinHttpCloseHandle(r);
        WinHttpCloseHandle(cn);
        WinHttpCloseHandle(s);
        return L"";
    }

    DWORD sz = 0, dl = 0;
    std::string ct;
    do {
        if (!WinHttpQueryDataAvailable(r, &sz) || !sz) break;
        char* bf = new char[sz + 1];
        ZeroMemory(bf, sz + 1);
        if (!WinHttpReadData(r, bf, sz, &dl)) {
            delete[] bf;
            break;
        }
        ct.append(bf, dl);
        delete[] bf;
    } while (sz > 0);

    WinHttpCloseHandle(r);
    WinHttpCloseHandle(cn);
    WinHttpCloseHandle(s);

    int rs = MultiByteToWideChar(CP_UTF8, 0, ct.c_str(), -1, 0, 0);
    if (rs <= 0) return L"";
    std::wstring wc(rs, 0);
    MultiByteToWideChar(CP_UTF8, 0, ct.c_str(), -1, &wc[0], rs);
    wc.resize(wc.find(L'\0'));
    return wc;
}

std::vector<P> ppd(const std::wstring& d) {
    std::vector<P> pp;
    std::wstringstream w(d);
    std::wstring l;
    P c;
    while (std::getline(w, l)) {
        size_t s = l.find_first_not_of(L" \t\r\n");
        if (s == std::wstring::npos) continue;
        l = l.substr(s, l.find_last_not_of(L" \t\r\n") - s + 1);
        if (l.empty() || l[0] == L'#') continue;

        if (l.find(L"process:") == 0) {
            if (!c.p.empty()) {
                pp.push_back(c);
                c = P();
            }
            c.p = l.substr(8);
            c.p.erase(0, c.p.find_first_not_of(L" \t"));
        }
        else if (l.find(L"module:") == 0) {
            std::wstring m = l.substr(7);
            size_t ms = m.find_first_not_of(L" \t");
            if (ms != std::wstring::npos) m = m.substr(ms);
            c.m = std::string(m.begin(), m.end());
        }
        else if (l.find(L"decimal:") != 0) {
            try {
                std::wstringstream pl(l);
                std::wstring a, x, n;
                if (std::getline(pl, a, L',') && std::getline(pl, x, L',') && std::getline(pl, n)) {
                    c.t.push_back({ std::stoull(a, 0, 10), (unsigned char)std::stoul(n, 0, 10) });
                }
                else if (std::getline(pl, a, L',') && std::getline(pl, n)) {
                    c.t.push_back({ std::stoull(a, 0, 10), (unsigned char)std::stoul(n, 0, 10) });
                }
            }
            catch (...) {}
        }
    }
    if (!c.p.empty()) pp.push_back(c);
    return pp;
}

std::vector<std::wstring> grp() {
    std::vector<std::wstring> p;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return p;
    PROCESSENTRY32W e;
    e.dwSize = sizeof(e);
    if (Process32FirstW(h, &e)) {
        do {
            p.push_back(e.szExeFile);
        } while (Process32NextW(h, &e));
    }
    CloseHandle(h);
    return p;
}

int main() {

    MUTATE_START
        SetConsoleTitleW(L"patcher | estdae");
    sg();
    MUTATE_END

    STR_ENCRYPT_START
        std::wstring d = dfc(L"https://pastebin.com/raw/");  // Replace the link
    STR_ENCRYPT_END

        if (d.empty()) {
            ap(L"fail");
            rc();
            return 1;
        }

    CODEREPLACE_START
        ap(L"Cracked by estdae");
    std::vector<P> p = ppd(d);
    CODEREPLACE_END

        if (!p.empty()) p = { p[0] };

    if (p.empty()) {
        ap(L"No patch data");
        rc();
        return 1;
    }

    CLEAR_START 
        std::vector<std::wstring> r = grp();
    std::vector<P> rp;

    for (auto pr : p) {
        if (std::find(r.begin(), r.end(), pr.p) != r.end()) {
            rp.push_back(pr);
            ap(L"process found");
        }
    }

    if (rp.empty()) {
        ap(L"No target running");
        rc();
        return 1;
    }
    CLEAR_END

        if (!enb()) return 1;

    VM_START  
        for (auto pr : rp) {
            DWORD pd = pid(pr.p);
            if (!pd) continue;

            STR_ENCRYPT_START
                HANDLE h = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, 0, pd);
            STR_ENCRYPT_END

                if (!h) continue;

            uintptr_t mb = gba(pd, pr.m.c_str());
            if (!mb) {
                CloseHandle(h);
                continue;
            }
                for (auto pt : pr.t) {
                    uintptr_t a = mb + pt.a;
                    SIZE_T bw;
                    WriteProcessMemory(h, (LPVOID)a, &pt.b, sizeof(pt.b), &bw);
                }
                ap(L"patched");
            CloseHandle(h);
        }
    VM_END

        MUTATE_START
        ap(L"press key");
    system("pause");
    MUTATE_END

        return 0;
}