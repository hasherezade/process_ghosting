#include "process_env.h"

#include "ntddk.h"
#include "ntdll_undoc.h"
#include "util.h"

#include <iostream>
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")

bool set_params_in_peb(PVOID params_base, HANDLE hProcess, PROCESS_BASIC_INFORMATION &pbi)
{
    // Get access to the remote PEB:
    ULONGLONG remote_peb_addr = (ULONGLONG)pbi.PebBaseAddress;
    if (!remote_peb_addr) {
        std::cerr << "Failed getting remote PEB address!" << std::endl;
        return false;
    }
    PEB peb_copy = { 0 };
    ULONGLONG offset = (ULONGLONG)&peb_copy.ProcessParameters - (ULONGLONG)&peb_copy;

    // Calculate offset of the parameters
    LPVOID remote_img_base = (LPVOID)(remote_peb_addr + offset);

    //Write parameters address into PEB:
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remote_img_base,
        &params_base, sizeof(PVOID),
        &written))
    {
        std::cout << "Cannot update Params!" << std::endl;
        return false;
    }
    return true;
}

bool buffer_remote_peb(HANDLE hProcess, PROCESS_BASIC_INFORMATION &pi, OUT PEB &peb_copy)
{
    memset(&peb_copy, 0, sizeof(PEB));
    PPEB remote_peb_addr = pi.PebBaseAddress;
#ifdef _DEBUG
    std::cout << "PEB address: " << (std::hex) << (ULONGLONG)remote_peb_addr << std::endl;
#endif 
    // Write the payload's ImageBase into remote process' PEB:
    NTSTATUS status = NtReadVirtualMemory(hProcess, remote_peb_addr, &peb_copy, sizeof(PEB), NULL);
    if (status != STATUS_SUCCESS)
    {
        std::cerr << "Cannot read remote PEB: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}


//Preserve the aligmnent! The remote address of the parameters must be the same as local.
LPVOID write_params_into_process(HANDLE hProcess, PRTL_USER_PROCESS_PARAMETERS params, DWORD protect)
{
    if (params == NULL) return NULL;

    PVOID buffer = params;
    ULONG_PTR buffer_end = (ULONG_PTR)params + params->Length;

    //params and environment in one space:
    if (params->Environment) {
        if ((ULONG_PTR)params > (ULONG_PTR)params->Environment) {
            buffer = (PVOID)params->Environment;
        }
        ULONG_PTR env_end = (ULONG_PTR)params->Environment + params->EnvironmentSize;
        if (env_end > buffer_end) {
            buffer_end = env_end;
        }
    }
    // copy the continuous area containing parameters + environment
    SIZE_T buffer_size = buffer_end - (ULONG_PTR)buffer;
    if (VirtualAllocEx(hProcess, buffer, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
        if (!WriteProcessMemory(hProcess, (LPVOID)params, (LPVOID)params, params->Length, NULL)) {
            std::cerr << "Writing RemoteProcessParams failed" << std::endl;
            return nullptr;
        }
        if (params->Environment) {
            if (!WriteProcessMemory(hProcess, (LPVOID)params->Environment, (LPVOID)params->Environment, params->EnvironmentSize, NULL)) {
                std::cerr << "Writing environment failed" << std::endl;
                return nullptr;
            }
        }
        return (LPVOID)params;
    }

    // could not copy the continuous space, try to fill it as separate chunks:
    if (!VirtualAllocEx(hProcess, (LPVOID)params, params->Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
        std::cerr << "Allocating RemoteProcessParams failed" << std::endl;
        return nullptr;
    }
    if (!WriteProcessMemory(hProcess, (LPVOID)params, (LPVOID)params, params->Length, NULL)) {
        std::cerr << "Writing RemoteProcessParams failed" << std::endl;
        return nullptr;
    }
    if (params->Environment) {
        if (!VirtualAllocEx(hProcess, (LPVOID)params->Environment, params->EnvironmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
            std::cerr << "Allocating environment failed" << std::endl;
            return nullptr;
        }
        if (!WriteProcessMemory(hProcess, (LPVOID)params->Environment, (LPVOID)params->Environment, params->EnvironmentSize, NULL)) {
            std::cerr << "Writing environment failed" << std::endl;
            return nullptr;
        }
    }
    return (LPVOID)params;
}


bool setup_process_parameters(HANDLE hProcess, PROCESS_BASIC_INFORMATION &pi, LPWSTR targetPath)
{
    //---
    UNICODE_STRING uTargetPath = { 0 };
    RtlInitUnicodeString(&uTargetPath, targetPath);
    //---
    wchar_t dirPath[MAX_PATH] = { 0 };
    get_directory(targetPath, dirPath, MAX_PATH);
    //if the directory is empty, set the current one
    if (wcsnlen(dirPath, MAX_PATH) == 0) {
        GetCurrentDirectoryW(MAX_PATH, dirPath);
    }
    UNICODE_STRING uCurrentDir = { 0 };
    RtlInitUnicodeString(&uCurrentDir, dirPath);
    //---
    wchar_t dllDir[] = L"C:\\Windows\\System32";
    UNICODE_STRING uDllDir = { 0 };
    RtlInitUnicodeString(&uDllDir, dllDir);
    //---
    UNICODE_STRING uWindowName = { 0 };
    wchar_t *windowName = L"Process Doppelganging test!";
    RtlInitUnicodeString(&uWindowName, windowName);

    LPVOID environment;
    CreateEnvironmentBlock(&environment, NULL, TRUE);

    PRTL_USER_PROCESS_PARAMETERS params = nullptr;
    NTSTATUS status = RtlCreateProcessParametersEx(
        &params,
        (PUNICODE_STRING)&uTargetPath,
        (PUNICODE_STRING)&uDllDir,
        (PUNICODE_STRING)&uCurrentDir,
        (PUNICODE_STRING)&uTargetPath,
        environment,
        (PUNICODE_STRING)&uWindowName,
        nullptr,
        nullptr,
        nullptr,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "RtlCreateProcessParametersEx failed" << std::endl;
        return false;
    }
    LPVOID remote_params = write_params_into_process(hProcess, params, PAGE_READWRITE);
    if (!remote_params) {
        std::cout << "[+] Cannot make a remote copy of parameters: " << GetLastError() << std::endl;
        return false;
    }
#ifdef _DEBUG
    std::cout << "[+] Parameters mapped!" << std::endl;
#endif
    PEB peb_copy = { 0 };
    if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
        return false;
    }

    if (!set_params_in_peb(remote_params, hProcess, pi)) {
        std::cout << "[+] Cannot update PEB: " << GetLastError() << std::endl;
        return false;
    }
#ifdef _DEBUG
    if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
        return false;
    }
    std::cout << "> ProcessParameters addr: " << peb_copy.ProcessParameters << std::endl;
#endif
    return true;
}
