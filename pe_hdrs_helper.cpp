#include "pe_hdrs_helper.h"

BYTE* get_nt_hrds(const BYTE *pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;

    if (pe_offset > kMaxOffset) return NULL;

    IMAGE_NT_HEADERS32 *inh = (IMAGE_NT_HEADERS32 *)(pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    return (BYTE*)inh;
}

WORD get_pe_architecture(const BYTE *pe_buffer)
{
    void *ptr = get_nt_hrds(pe_buffer);
    if (ptr == NULL) return 0;

    IMAGE_NT_HEADERS32 *inh = static_cast<IMAGE_NT_HEADERS32*>(ptr);
    return inh->FileHeader.Machine;
}

DWORD get_entry_point_rva(const BYTE *pe_buffer)
{
    WORD arch = get_pe_architecture(pe_buffer);
    BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
    if (payload_nt_hdr == NULL) {
        return 0;
    }
        DWORD ep_addr = 0;
    if (arch == IMAGE_FILE_MACHINE_AMD64) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        ep_addr = payload_nt_hdr64->OptionalHeader.AddressOfEntryPoint;
    } else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        ep_addr = static_cast<ULONGLONG>(payload_nt_hdr32->OptionalHeader.AddressOfEntryPoint);
    }
    return ep_addr;
}
