#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <sstream>
#include <iomanip>

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

HWND hLogBox;

void ListProcesses(HWND hwnd) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        SendMessage(hLogBox, WM_SETTEXT, 0, (LPARAM)L"Error: Unable to create process snapshot.");
        return;
    }

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        SendMessage(hLogBox, WM_SETTEXT, 0, (LPARAM)L"Error: Unable to get process information.");
        return;
    }

    std::wstring processList;
    do {
        processList += L"Process: " + std::wstring(pe32.szExeFile) + L" | PID: " + std::to_wstring(pe32.th32ProcessID) + L"\r\n";
    } while (Process32Next(hProcessSnap, &pe32));

    SendMessage(hLogBox, WM_SETTEXT, 0, (LPARAM)processList.c_str());
    CloseHandle(hProcessSnap);
}

std::vector<BYTE> HexStringToBytes(const std::wstring& hex) {
    std::vector<BYTE> bytes;
    std::wstringstream hexStream(hex);
    std::wstring byteString;

    while (hexStream >> byteString) {
        BYTE byte = static_cast<BYTE>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

bool PatchProcessMemory(DWORD pid, LPVOID address, BYTE* newBytes, SIZE_T byteSize, HWND hwnd) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        SendMessage(hLogBox, WM_SETTEXT, 0, (LPARAM)L"Error: Unable to open process.");
        return false;
    }

    BYTE oldBytes[8];
    if (!ReadProcessMemory(hProcess, address, oldBytes, byteSize, nullptr)) {
        SendMessage(hLogBox, WM_SETTEXT, 0, (LPARAM)L"Error: Unable to read memory.");
        CloseHandle(hProcess);
        return false;
    }

    std::wstring oldBytesStr = L"Old Bytes: ";
    for (SIZE_T i = 0; i < byteSize; i++) {
        oldBytesStr += std::to_wstring(oldBytes[i]) + L" ";
    }
    SendMessage(hLogBox, WM_SETTEXT, 0, (LPARAM)oldBytesStr.c_str());

    if (!WriteProcessMemory(hProcess, address, newBytes, byteSize, nullptr)) {
        SendMessage(hLogBox, WM_SETTEXT, 0, (LPARAM)L"Error: Unable to write memory.");
        CloseHandle(hProcess);
        return false;
    }

    SendMessage(hLogBox, WM_SETTEXT, 0, (LPARAM)L"Patch applied successfully.");
    CloseHandle(hProcess);
    return true;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nShowCmd) {
    const wchar_t CLASS_NAME[] = L"Sample Window Class";

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(0, CLASS_NAME, L"Memory Patcher", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, nullptr, nullptr, hInstance, nullptr);

    ShowWindow(hwnd, nShowCmd);
    UpdateWindow(hwnd);

    ListProcesses(hwnd);

    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HWND hPidInput, hAddressInput, hBytesInput, hPatchButton;

    switch (uMsg) {
    case WM_CREATE:
        CreateWindow(L"STATIC", L"PID:", WS_VISIBLE | WS_CHILD, 10, 10, 50, 20, hwnd, nullptr, nullptr, nullptr);
        hPidInput = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 70, 10, 100, 20, hwnd, nullptr, nullptr, nullptr);

        CreateWindow(L"STATIC", L"Address:", WS_VISIBLE | WS_CHILD, 10, 40, 50, 20, hwnd, nullptr, nullptr, nullptr);
        hAddressInput = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 70, 40, 100, 20, hwnd, nullptr, nullptr, nullptr);

        CreateWindow(L"STATIC", L"New Bytes:", WS_VISIBLE | WS_CHILD, 10, 70, 80, 20, hwnd, nullptr, nullptr, nullptr);
        hBytesInput = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 100, 70, 170, 20, hwnd, nullptr, nullptr, nullptr);

        hPatchButton = CreateWindow(L"BUTTON", L"Patch Memory", WS_VISIBLE | WS_CHILD, 10, 100, 100, 30, hwnd, nullptr, nullptr, nullptr);
        hLogBox = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY, 10, 140, 360, 120, hwnd, nullptr, nullptr, nullptr);

        SendMessage(hLogBox, EM_SETREADONLY, TRUE, 0);
        break;
    case WM_COMMAND:
        if ((HWND)lParam == hPatchButton) {
            DWORD pid = GetDlgItemInt(hwnd, (int)hPidInput, nullptr, FALSE);
            std::wstring addressStr(256, L'\0');
            GetWindowText(hAddressInput, &addressStr[0], addressStr.size());
            uintptr_t address = std::stoul(addressStr.c_str(), nullptr, 16);

            wchar_t newBytesStr[256];
            GetWindowText(hBytesInput, newBytesStr, sizeof(newBytesStr) / sizeof(newBytesStr[0]));

            std::vector<BYTE> newBytes = HexStringToBytes(newBytesStr);
            SIZE_T byteSize = newBytes.size();

            if (!PatchProcessMemory(pid, (LPVOID)address, newBytes.data(), byteSize, hwnd)) {
                SendMessage(hLogBox, WM_SETTEXT, 0, (LPARAM)L"Memory patching failed.");
            }
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
