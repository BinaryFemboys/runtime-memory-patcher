#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <string>
#include <algorithm>

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define MAGENTA "\033[35m"

void EnableANSIColors() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) return;

    DWORD mode = 0;
    GetConsoleMode(hConsole, &mode);
    SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

bool SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, Privilege, &luid)) {
        std::cout << RED << "Error: Unable to look up privilege value." << RESET << std::endl;
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cout << RED << "Error: Unable to adjust token privileges." << RESET << std::endl;
        return false;
    }

    return true;
}

void EnableDebugPrivilege() {
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
        CloseHandle(hToken);
    }
    else {
        std::cout << RED << "Error: Unable to open process token." << RESET << std::endl;
    }
}

DWORD FindProcessIdByName(const std::wstring& processName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cout << RED << "Error: Unable to create process snapshot." << RESET << std::endl;
        return 0;
    }

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        std::cout << RED << "Error: Unable to get process information." << RESET << std::endl;
        return 0;
    }

    do {
        if (processName == pe32.szExeFile) {
            CloseHandle(hProcessSnap);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    std::cout << RED << "Error: Process not found." << RESET << std::endl;
    return 0;
}

std::vector<BYTE> HexStringToBytes(const std::string& hex) {
    std::vector<BYTE> bytes;
    std::istringstream hexStream(hex);
    std::string byteString;

    while (hexStream >> byteString) {
        BYTE byte = static_cast<BYTE>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

bool PatchProcessMemory(DWORD pid, LPVOID address, BYTE* newBytes, SIZE_T byteSize) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cout << RED << "Error: Unable to open process." << RESET << std::endl;
        return false;
    }

    BYTE oldBytes[8];
    if (!ReadProcessMemory(hProcess, address, oldBytes, byteSize, nullptr)) {
        std::cout << RED << "Error: Unable to read memory." << RESET << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "Old Bytes: ";
    for (SIZE_T i = 0; i < byteSize; i++) {
        printf("%02X ", oldBytes[i]);
    }
    std::cout << std::endl;

    if (!WriteProcessMemory(hProcess, address, newBytes, byteSize, nullptr)) {
        std::cout << RED << "Error: Unable to write memory." << RESET << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    std::cout << GREEN << "Patch applied successfully." << RESET << std::endl;
    CloseHandle(hProcess);
    return true;
}

void RequestElevation() {
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken)) {
        DWORD dwSize;
        GetTokenInformation(hToken, TokenElevation, &dwSize, sizeof(dwSize), &dwSize);
        TOKEN_ELEVATION* pTokenElevation = (TOKEN_ELEVATION*)malloc(dwSize);
        if (pTokenElevation) {
            if (GetTokenInformation(hToken, TokenElevation, pTokenElevation, dwSize, &dwSize)) {
                if (!pTokenElevation->TokenIsElevated) {
                    std::cout << RED << "Requesting administrative privileges..." << RESET << std::endl;
                    std::string command = "powershell -Command \"Start-Process '" + std::string(__argv[0]) + "' -Verb RunAs\"";
                    system(command.c_str());
                    ExitProcess(0);
                }
            }
            free(pTokenElevation);
        }
        CloseHandle(hToken);
    }
}

int main() {
    RequestElevation();
    EnableDebugPrivilege();
    EnableANSIColors();
    std::cout << YELLOW
        << R"(
 ____  _                           ______ ____  
|  _ \(_)                         |  ____|  _ \ 
| |_) |_ _ __   __ _ _ __ _   _   | |__  | |_) |
|  _ <| | '_ \ / _` | '__| | | |  |  __| |  _ < 
| |_) | | | | | (_| | |  | |_| |  | |    | |_) |
|____/|_|_| |_|\__,_|_|   \__, |  |_|    |____/ 
                           __/ |                
                          |___/            
)"
<< RESET << std::endl;

    std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << GREEN << " [INFO] You like femboys don't you~~ ;3" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << GREEN << " [INFO] Currently using Binary Femboys v1.2" << std::endl;
    std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << GREEN << " [INFO] Made with love (and several lost braincells) by @od8m and @deltrix" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(2));

    while (true) {
        std::string input;
        std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << GREEN << " [INFO] Enter process name or PID: " << RESET;
        std::cin >> input;

        DWORD pid;
        if (std::all_of(input.begin(), input.end(), ::isdigit)) {
            pid = std::stoul(input);
        }
        else {
            pid = FindProcessIdByName(std::wstring(input.begin(), input.end()));
        }

        uintptr_t address;
        std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << GREEN << "[INFO] Enter address to patch: " << RESET;
        std::cin >> std::hex >> address;

        std::string inputBytes;
        std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << GREEN << "[INFO] Enter new bytes: " << RESET;
        std::cin.ignore();
        std::getline(std::cin, inputBytes);

        std::vector<BYTE> newBytes = HexStringToBytes(inputBytes);
        SIZE_T byteSize = newBytes.size();

        std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << GREEN << "[INFO] Patching memory..." << RESET << std::endl;
        if (!PatchProcessMemory(pid, (LPVOID)address, newBytes.data(), byteSize)) {
            std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << RED << "[ERROR] Memory patching failed." << RESET << std::endl;
        }

        std::cout << MAGENTA << "[BinaryFemboy Central]" << RESET << GREEN << "[INFO] Do you want to patch another address? (y/n): " << RESET;
        char choice;
        std::cin >> choice;
        if (choice != 'y' && choice != 'Y') {
            break;
        }
    }

    return 0;
}
