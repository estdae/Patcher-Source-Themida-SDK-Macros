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

constexpr int DEFAULT_TEXT_DELAY_MS = 30;
constexpr wchar_t PASTEBIN_URL[] = L"https://pastebin.com/raw/"; // Replace the link

bool enableDebugPrivilege() {
    HANDLE tokenHandle;
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle)) return false;

    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        CloseHandle(tokenHandle);
        return false;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), nullptr, nullptr)) {
        CloseHandle(tokenHandle);
        return false;
    }

    CloseHandle(tokenHandle);
    return true;
}

DWORD getProcessIdByName(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry = { sizeof(entry) };
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(processName.c_str(), entry.szExeFile) == 0) {
                processId = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return processId;
}

struct WindowTitleChanger {
    DWORD processId;
    std::wstring newTitle;
    bool success;
};

BOOL CALLBACK enumWindowsProc(HWND hwnd, LPARAM lParam) {
    auto* data = reinterpret_cast<WindowTitleChanger*>(lParam);
    DWORD windowProcessId;
    GetWindowThreadProcessId(hwnd, &windowProcessId);

    if (windowProcessId == data->processId && IsWindowVisible(hwnd)) {
        if (SetWindowTextW(hwnd, data->newTitle.c_str())) {
            data->success = true;
        }
    }

    return TRUE;
}

bool changeWindowTitle(DWORD processId, const std::wstring& newTitle) {
    WindowTitleChanger changer = { processId, newTitle, false };
    EnumWindows(enumWindowsProc, reinterpret_cast<LPARAM>(&changer));
    return changer.success;
}

void setGreenText() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}

void resetConsoleColor() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void animatedPrint(const std::wstring& text, int delayMs = DEFAULT_TEXT_DELAY_MS) {
    for (wchar_t ch : text) {
        std::wcout << ch << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
    }
    std::wcout << std::endl;
}

struct PatchTarget {
    uintptr_t offset;
    unsigned char value;
};

struct PatchConfig {
    std::wstring processName;
    std::wstring moduleName;
    std::vector<PatchTarget> patches;
};

uintptr_t getModuleBaseAddress(DWORD processId, const wchar_t* moduleName) {
    uintptr_t baseAddress = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W moduleEntry = { sizeof(moduleEntry) };
    if (Module32FirstW(snapshot, &moduleEntry)) {
        do {
            if (_wcsicmp(moduleEntry.szModule, moduleName) == 0) {
                baseAddress = reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr);
                break;
            }
        } while (Module32NextW(snapshot, &moduleEntry));
    }

    CloseHandle(snapshot);
    return baseAddress;
}

std::wstring downloadPatchConfig(const std::wstring& url) {
    URL_COMPONENTS components = { sizeof(components) };
    wchar_t host[256];
    wchar_t path[1024];

    components.lpszHostName = host;
    components.dwHostNameLength = 256;
    components.lpszUrlPath = path;
    components.dwUrlPathLength = 1024;

    if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.length()), 0, &components)) return L"";

    HINTERNET session = WinHttpOpen(L"PF", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
    if (!session) return L"";

    HINTERNET connection = WinHttpConnect(session, components.lpszHostName, components.nPort, 0);
    if (!connection) {
        WinHttpCloseHandle(session);
        return L"";
    }

    HINTERNET request = WinHttpOpenRequest(
        connection, L"GET", components.lpszUrlPath,
        nullptr, nullptr, nullptr,
        components.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0
    );

    if (!request || !WinHttpSendRequest(request, nullptr, 0, nullptr, 0, 0, 0) || !WinHttpReceiveResponse(request, nullptr)) {
        if (request) WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return L"";
    }

    DWORD availableSize = 0, bytesRead = 0;
    std::string content;

    do {
        if (!WinHttpQueryDataAvailable(request, &availableSize) || availableSize == 0) break;
        char* buffer = new char[availableSize + 1]();
        if (!WinHttpReadData(request, buffer, availableSize, &bytesRead)) {
            delete[] buffer;
            break;
        }
        content.append(buffer, bytesRead);
        delete[] buffer;
    } while (availableSize > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    int wideSize = MultiByteToWideChar(CP_UTF8, 0, content.c_str(), -1, nullptr, 0);
    if (wideSize <= 0) return L"";

    std::wstring result(wideSize, 0);
    MultiByteToWideChar(CP_UTF8, 0, content.c_str(), -1, &result[0], wideSize);
    result.resize(result.find(L'\0'));

    return result;
}

std::vector<PatchConfig> parsePatchData(const std::wstring& rawData) {
    std::vector<PatchConfig> configs;
    std::wstringstream stream(rawData);
    std::wstring line;
    PatchConfig currentConfig;

    while (std::getline(stream, line)) {
        size_t start = line.find_first_not_of(L" \t\r\n");
        if (start == std::wstring::npos) continue;

        line = line.substr(start, line.find_last_not_of(L" \t\r\n") - start + 1);
        if (line.empty() || line[0] == L'#') continue;

        if (line.find(L"process:") == 0) {
            if (!currentConfig.processName.empty()) {
                configs.push_back(currentConfig);
                currentConfig = PatchConfig();
            }
            currentConfig.processName = line.substr(8);
            currentConfig.processName.erase(0, currentConfig.processName.find_first_not_of(L" \t"));
        } else if (line.find(L"module:") == 0) {
            std::wstring mod = line.substr(7);
            size_t modStart = mod.find_first_not_of(L" \t");
            if (modStart != std::wstring::npos) mod = mod.substr(modStart);
            currentConfig.moduleName = mod;
        } else if (line.find(L"decimal:") != 0) {
            try {
                std::wstringstream patchLine(line);
                std::wstring addrStr, _, valueStr;

                if ((std::getline(patchLine, addrStr, L',') && std::getline(patchLine, _, L',') && std::getline(patchLine, valueStr)) ||
                    (std::getline(patchLine, addrStr, L',') && std::getline(patchLine, valueStr))) {
                    currentConfig.patches.push_back({ std::stoull(addrStr, nullptr, 10), static_cast<unsigned char>(std::stoul(valueStr, nullptr, 10)) });
                }
            } catch (...) {
            }
        }
    }

    if (!currentConfig.processName.empty()) configs.push_back(currentConfig);
    return configs;
}

std::vector<std::wstring> getRunningProcesses() {
    std::vector<std::wstring> processNames;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return processNames;

    PROCESSENTRY32W entry = { sizeof(entry) };
    if (Process32FirstW(snapshot, &entry)) {
        do {
            processNames.push_back(entry.szExeFile);
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return processNames;
}

int main() {
    MUTATE_START
        SetConsoleTitleW(L"patcher | estdae");
    setGreenText();
    MUTATE_END

    STR_ENCRYPT_START
        std::wstring configData = downloadPatchConfig(PASTEBIN_URL);
    STR_ENCRYPT_END

    if (configData.empty()) {
        animatedPrint(L"Failed to download patch data");
        resetConsoleColor();
        return 1;
    }

    CODEREPLACE_START
        animatedPrint(L"Cracked by estdae");
        std::vector<PatchConfig> patchConfigs = parsePatchData(configData);
    CODEREPLACE_END

    if (!patchConfigs.empty()) patchConfigs = { patchConfigs[0] };

    if (patchConfigs.empty()) {
        animatedPrint(L"No patch data available");
        resetConsoleColor();
        return 1;
    }

    CLEAR_START 
        std::vector<std::wstring> runningProcesses = getRunningProcesses();
        std::vector<PatchConfig> targets;

        for (const auto& patch : patchConfigs) {
            auto it = std::find_if(
                runningProcesses.begin(), runningProcesses.end(),
                [&](const std::wstring& proc) {
                    return _wcsicmp(proc.c_str(), patch.processName.c_str()) == 0;
                });

            if (it != runningProcesses.end()) {
                targets.push_back(patch);
                animatedPrint(L"Target process found: " + patch.processName);
            }
        }

        if (targets.empty()) {
            animatedPrint(L"No target processes running");
            resetConsoleColor();
            return 1;
        }
    CLEAR_END

    if (!enableDebugPrivilege()) return 1;

    VM_START  
        for (const auto& target : targets) {
            DWORD targetPid = getProcessIdByName(target.processName);
            if (!targetPid) continue;

            STR_ENCRYPT_START
                HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, targetPid);
            STR_ENCRYPT_END

            if (!hProcess) continue;

            uintptr_t moduleBase = getModuleBaseAddress(targetPid, target.moduleName.c_str());
            if (!moduleBase) {
                CloseHandle(hProcess);
                continue;
            }

            for (const auto& patch : target.patches) {
                uintptr_t address = moduleBase + patch.offset;
                SIZE_T bytesWritten;
                WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(address), &patch.value, sizeof(patch.value), &bytesWritten);
            }

            animatedPrint(L"Successfully patched: " + target.processName);
            CloseHandle(hProcess);
        }
    VM_END

    MUTATE_START
        system("pause");
    MUTATE_END

    return 0;
}
