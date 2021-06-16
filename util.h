#pragma once

#include <Windows.h>

BYTE *buffer_payload(wchar_t *filename, OUT size_t &r_size);
void free_buffer(BYTE* buffer, size_t buffer_size);

//get file name from the full path
wchar_t* get_file_name(wchar_t *full_path);

wchar_t* get_directory(IN wchar_t *full_path, OUT wchar_t *out_buf, IN const size_t out_buf_size);

bool get_calc_path(LPWSTR lpwOutPath, DWORD szOutPath, bool isPayl32bit);
