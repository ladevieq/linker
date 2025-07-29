// #include <winternl.h>
#include <Windows.h>
#include <strsafe.h>

#include <stdint.h>
#include <winnt.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

static const u32 TEXT_SECTION_FLAGS = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
static const u32 DRECTVE_SECTION_FLAGS = (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
static const u64 lib_signature = 0x0A3E686372613C21; // IMAGE_ARCHIVE_START

#define ALIGN(x, align) (((x) + (align - 1U)) / (align)) * (align)

#define ASSERT(x) if (!(x)) { __debugbreak(); }

struct coff_header {
    u16 machine_type;
    u16 sections_count;
    u32 timestamp;
    u32 symbol_table_offset;
    u32 symbols_count;
    u16 optional_header_size;
    u16 characteristics;
};

#pragma pack(1)
struct coff_symbol {
    union {
        u8 name[8U];
        struct {
            u32 zeroes;
            u32 offset;
        };
    };
    u32 value;
    i16 section_number;
    u16 type;
    u8 storage_class;
    u8 number_of_aux_symbols;
};

// https://learn.microsoft.com/en-us/windows/win32/Debug/pe-format#section-table-section-headers
struct section_header {
    u8  name[8U];
    u32 virtual_size;
    u32 virtual_addr;
    u32 size_of_raw_data;
    u32 pointer_to_raw_data;
    u32 pointer_to_relocations;
    u32 pointer_to_line_numbers;
    u16 number_of_relocations;
    u16 number_of_line_numbers;
    u32 characteristics;
};

struct base_relocation_block {
    u32 page_rva;
    u32 block_size;
};

struct relocation_entry {
    // u16 type: 4;
    // u16 offset: 12;

    u32 virtual_address;
    u32 symbol_index;
    u16 type;
};

static u8 is_alpha(char c) {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
}

static u8 is_decimal_digit(char c) {
    return '0' <= c && c <= '9';
}

// TODO: Improve
static void mem_copy(void* src, void* dst, size_t size) {
    u8* byte_src = (u8*)src;
    u8* byte_dst = (u8*)dst;

    for (u32 index = 0U; index < size; index++) {
        byte_dst[index] = byte_src[index];
    }
}

static void mem_set(void* ptr, size_t size, u8 value) {
    u8* bytes = ptr;
    for (u32 index = 0U; index < size; index++) {
        bytes[index] = value;
    }
}

static void u64toa(u64 number, char* str, u32 base) {
    static char codes[16U] = {
        '0',
        '1',
        '2',
        '3',
        '4',
        '5',
        '6',
        '7',
        '8',
        '9',
        'A',
        'B',
        'C',
        'D',
        'E',
        'F',
    };
    u32 remainder = 0U;
    u32 size = 0U;

    if (number == 0) {
        str[0U] = codes[0U];
        return;
    }

    for(; number != 0U; size++) {
        remainder = number % base;
        number /= base;
        str[size] = codes[remainder];
    }

    for(u32 i = 0; i < size / 2U; i++) {
        char c = str[i];
        str[i] = str[size - i - 1];
        str[size - i - 1] = c;
    }
}

static u64 atou64(const char* str, u32 len) {
    u64 number = 0U;
    u32 base = 10U;
    const char* c = str;

    if (str[0] == '0' && str[1] == 'x') {
        base = 16U;
        c += 2U;
    }

    for (; (u32)(c - str) < len; c++) {
        number *= base;
        u8 offset = 0U;
        if ('0' <= *c && *c <= '9') {
            offset = 48U;
        } else if ('a' <= *c && *c <= 'f') {
            offset = 87U;
        } else if ('A' <= *c && *c <= 'F') {
            offset = 55U;
        } else {
            return 0;
        }

        ASSERT(0 <= *c)
        number += ((u8)*c - offset);
    }

    return number;
}

static void print(const char* format, ...) {
    va_list args;
    va_start(args, format);
    char formatted_str[4096U] = { 0 };
    STRSAFE_LPSTR cur_char = formatted_str;

    const char* cur_fmt = format;
    while(*cur_fmt != '\0') {
        if(*cur_fmt == '%') {
            cur_fmt++;
            if (*cur_fmt == 's') {
                const char* str = va_arg(args, const char*);
                size_t length = 0U;
                if (cur_fmt[1U] == '.') {
                    const char* number_start = &cur_fmt[2U];
                    u32 size = 0U;
                    while(is_decimal_digit(*(number_start + size))) {
                        size++;
                    }
                    if (size > 0U) {
                        length = (size_t)atou64(number_start, size);
                    }
                    cur_fmt += size + 1U;
                }
                if (length == 0U) {
                    StringCchLengthA(str, sizeof(formatted_str), &length);
                }
                if(str != NULL) {
                    StringCchCatA(cur_char, length + 1U, str);
                    cur_char += length;
                }
            } else if(*cur_fmt == 'c') {
                char c = (char)va_arg(args, int);
                StringCchCatA(cur_char, 1U, &c);
                cur_char += 1U;
            } else if (*cur_fmt == 'x' && is_alpha(cur_fmt[1])) {
                u32 base = 16U;
                *cur_char = '0';
                cur_char++;
                *cur_char = 'x';
                cur_char++;
                cur_fmt++;

                if(*cur_fmt == 'b') {
                    u8 number = (u8)va_arg(args, int);
                    u64toa((u64)number, cur_char, base);
                    size_t length = 0U;
                    StringCchLengthA(formatted_str, sizeof(formatted_str), &length);
                    cur_char = formatted_str + length;
                } else if(*cur_fmt == 'u') {
                    u64 number = va_arg(args, u64);
                    u64toa(number, cur_char, base);
                    size_t length = 0U;
                    StringCchLengthA(formatted_str, sizeof(formatted_str), &length);
                    cur_char = formatted_str + length;
                }
            } else if(*cur_fmt == 'b') {
                u8 number = (u8)va_arg(args, int);
                u64toa((u64)number, cur_char, 10U);
                size_t length = 0U;
                StringCchLengthA(formatted_str, sizeof(formatted_str), &length);
                cur_char = formatted_str + length;
            } else if(*cur_fmt == 'u') {
                u64 number = va_arg(args, u64);
                u64toa(number, cur_char, 10U);
                size_t length = 0U;
                StringCchLengthA(formatted_str, sizeof(formatted_str), &length);
                cur_char = formatted_str + length;
            }
        } else {
            *cur_char = *cur_fmt;
            cur_char++;
        }
        cur_fmt++;
    }
    va_end(args);

    HANDLE standard_err = GetStdHandle(STD_ERROR_HANDLE);

    ASSERT(((u8*)cur_char - (u8*)formatted_str) < 0xffffffff)
    DWORD length = (DWORD)((u8*)cur_char - (u8*)formatted_str);
    SUCCEEDED(WriteFile(standard_err, formatted_str, length, NULL, NULL));
}

static void read_COFF(u8* buffer) {
    u8* next_byte = buffer;
    struct coff_header header = *(struct coff_header*)next_byte;
    next_byte += sizeof(header);

    if (header.machine_type == IMAGE_FILE_MACHINE_AMD64) {
        print("MACHINE: x64\n");
    }

    print("SECTIONS: %u\n", header.sections_count);
    print("SYMBOLS COUNT: %u\n", header.symbols_count);

    if (header.optional_header_size > 0U) {
        IMAGE_OPTIONAL_HEADER64 optional_header = *(IMAGE_OPTIONAL_HEADER64*)next_byte;
        print("MAGIC: %u\n", optional_header.Magic);
        next_byte += header.optional_header_size;
    }

    struct coff_symbol* symbol_table = (struct coff_symbol*)(buffer + header.symbol_table_offset);
    u8* string_table = (u8*)symbol_table + sizeof(*symbol_table) * header.symbols_count;

    struct section_header* sections = (struct section_header*)next_byte;
    next_byte += sizeof(sections[0]) * header.sections_count;
    for (u32 section_index = 0U; section_index < header.sections_count; section_index++) {
        struct section_header* section = &sections[section_index];
        print("SECTION NAME: %s\n", section->name);
        print("SECTION OFFSET: %u\n", section->pointer_to_raw_data);
        print("SECTION SIZE: %u\n", section->size_of_raw_data);
        print("SECTION RELOCATIONS COUNT: %u\n", section->number_of_relocations);

        u8* reloc_start = &buffer[section->pointer_to_relocations];
        struct relocation_entry* cur_reloc_entry = (struct relocation_entry*)reloc_start;

        for (u32 reloc_index = 0U; reloc_index < section->number_of_relocations; reloc_index++, cur_reloc_entry++) {
            print("SYMBOL INDEX : %u\n", cur_reloc_entry->symbol_index);

            struct coff_symbol* sym = symbol_table;
            for (u32 symbol_index = 0U; symbol_index < cur_reloc_entry->symbol_index; symbol_index++, sym++) {
            }
            if (sym->zeroes == 0U) {
                print("SYMBOL NAME : %s\n", string_table + sym->offset);
            } else {
                print("SYMBOL NAME : %s.8\n", sym->name);
            }

            // if (cur_reloc_entry->type == IMAGE_REL_AMD64_ABSOLUTE) {
            //     print("IMAGE_REL_AMD64_ABSOLUTE\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_ADDR64) {
            //     print("IMAGE_REL_AMD64_ADDR64\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_ADDR32) {
            //     print("IMAGE_REL_AMD64_ADDR32\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_ADDR32NB) {
            //     print("IMAGE_REL_AMD64_ADDR32NB\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_REL32) {
            //     print("IMAGE_REL_AMD64_REL32\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_REL32_1) {
            //     print("IMAGE_REL_AMD64_REL32_1\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_REL32_2) {
            //     print("IMAGE_REL_AMD64_REL32_2\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_REL32_3) {
            //     print("IMAGE_REL_AMD64_REL32_3\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_REL32_4) {
            //     print("IMAGE_REL_AMD64_REL32_4\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_REL32_5) {
            //     print("IMAGE_REL_AMD64_REL32_5\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_SECTION) {
            //     print("IMAGE_REL_AMD64_SECTION\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_SECREL) {
            //     print("IMAGE_REL_AMD64_SECREL\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_SECREL7) {
            //     print("IMAGE_REL_AMD64_SECREL7\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_TOKEN) {
            //     print("IMAGE_REL_AMD64_TOKEN\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_SREL32) {
            //     print("IMAGE_REL_AMD64_SREL32\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_PAIR) {
            //     print("IMAGE_REL_AMD64_PAIR\n");
            // } else if (cur_reloc_entry->type == IMAGE_REL_AMD64_SSPAN32) {
            //     print("IMAGE_REL_AMD64_SSPAN32\n");
            // }
        }

        if (section->characteristics & IMAGE_SCN_LNK_INFO) // .drectve
        {
            u8* drectve_start = &buffer[section->pointer_to_raw_data];
            print("%s\n", drectve_start);
        } else if ((section->characteristics & DRECTVE_SECTION_FLAGS) == DRECTVE_SECTION_FLAGS) { // .data
            u8* data_start = &buffer[section->pointer_to_raw_data];
            u8* cur_data = data_start;
            while ((cur_data - data_start) < section->size_of_raw_data) {
                size_t len = 0U;
                StringCchLengthA((STRSAFE_LPSTR)cur_data, section->size_of_raw_data, &len);
                if (len == 0U) {
                    cur_data++;
                } else {
                    print("%s\n", cur_data);
                    cur_data += len;
                }
            }
        } else if ((section->characteristics & TEXT_SECTION_FLAGS) == TEXT_SECTION_FLAGS) { // .text
            // u8* text_start = &buffer[section->pointer_to_raw_data];
        }
    }

    struct coff_symbol* cur_symbol = symbol_table;
    for (u32 symbol_index = 0U; symbol_index < header.symbols_count; symbol_index++, cur_symbol++) {

        if (cur_symbol->zeroes == 0U) {
            print("SYMBOL NAME : %s\n", string_table + cur_symbol->offset);
        } else {
            print("SYMBOL NAME : %s.8\n", cur_symbol->name);
        }

        if (cur_symbol->section_number > 1) {
            print("SECTION: %s\n", sections[(u16)cur_symbol->section_number - 1U].name);
        } else if (cur_symbol->section_number == IMAGE_SYM_UNDEFINED) {
            print("SECTION: EXTERNAL SYMBOL\n");
        } else if (cur_symbol->section_number == IMAGE_SYM_ABSOLUTE) {
            print("SECTION: ABSOLUTE\n");
        } else if (cur_symbol->section_number == IMAGE_SYM_DEBUG) {
            print("SECTION: DEBUG\n");
        }

        if (cur_symbol->number_of_aux_symbols > 0U) {
            cur_symbol += cur_symbol->number_of_aux_symbols;
            symbol_index++;
        }
    }
}

struct archive_member_header {
    u8 name[16U];
    u8 data[12U];
    u8 userID[6U];
    u8 groupID[6U];
    u64 mode;
    u8 size[10U];
    u16 end;
};

struct import_header {
    u16 sig1;
    u16 sig2;
    u16 version;
    u16 machine;
    u32 timestamp;
    u32 size;
    u16 ordinal;
    u16 import_type:    2;
    u16 name_type:      3;
    u16 reserved:       11;
};

#define BSWAP32(x) ((x & 0x000000FF) << 24U) | ((x & 0x0000FF00) << 8U) | ((x & 0x00FF0000) >> 8U) | ((x & 0xFF000000) >> 24U)

static void read_lib(u8* buffer) {
    u8* next_byte = buffer;

    {
        print("FIRST LINKER MEMBER\n");
        struct archive_member_header* first_linker_member = (struct archive_member_header*)next_byte;
        next_byte += sizeof(*first_linker_member);
        if (first_linker_member->name[0U] != '/') { // IMAGE_ARCHIVE_LINKER_MEMBER
            return;
        }

        u32 symbols_count = BSWAP32(*(u32*)next_byte);
        next_byte += sizeof(symbols_count);

        u32* first_linker_offsets = (u32*)next_byte;
        next_byte += sizeof(*first_linker_offsets) * symbols_count;

        u8* first_linker_string_table = next_byte;
        u8* cur_string = first_linker_string_table;
        for (u32 index = 0U; index < symbols_count; index++) {
            size_t size = 0U;
            StringCchLengthA((const char*)cur_string, 256U, &size);
            print("%s\n", cur_string);
            cur_string += size + 1U;
        }

        next_byte += cur_string - first_linker_string_table;
    }

    u32 archive_members_count = 0U;
    {
        print("SECOND LINKER MEMBER\n");
        struct archive_member_header* second_linker_member = (struct archive_member_header*)next_byte;
        next_byte += sizeof(*second_linker_member);
        if (second_linker_member->name[0U] != '/') { // IMAGE_ARCHIVE_LINKER_MEMBER
            return;
        }

        archive_members_count = *(u32*)next_byte;
        next_byte += sizeof(archive_members_count);

        u32* archive_members_offsets = (u32*)next_byte;
        next_byte += sizeof(*archive_members_offsets) * archive_members_count;

        u32 symbols_count = *(u32*)next_byte;
        next_byte += sizeof(symbols_count);

        u16* symbols_indices = (u16*)next_byte;
        next_byte += sizeof(*symbols_indices) * symbols_count;

        u8* second_linker_string_table = next_byte;
        u8* cur_string = second_linker_string_table;
        for (u32 index = 0U; index < symbols_count; index++) {
            size_t size = 0U;
            StringCchLengthA((const char*)cur_string, 256U, &size);
            print("%s\n", cur_string);
            cur_string += size + 1U;
        }
        next_byte += cur_string - second_linker_string_table;
    }

    {
        struct archive_member_header* longnames_member = (struct archive_member_header*)next_byte;
        if (longnames_member->name[0U] == '/' && longnames_member->name[1U] == '/') { // IMAGE_ARCHIVE_LONGNAMES_MEMBER
            next_byte += sizeof(*longnames_member);
        }
    }

    print("ARCHIVE COUNT: %u\n", archive_members_count);
    for (u32 archive_index = 0U; archive_index < archive_members_count; archive_index++) {
        next_byte += (u64)next_byte % 2U;
        struct archive_member_header* header = (struct archive_member_header*)next_byte;
        next_byte += sizeof(*header);

        u32 size = 0U;
        for (u8* c = (u8*)header->size; *c != 0x20 && size< sizeof(header->size) / sizeof(header->size[0U]); c++, size++) {
        }
        u64 archive_size = atou64((char*)header->size, size);


        print("ARCHIVE NAME: %s.16\n", header->name);
        print("ARCHIVE SIZE: %s.10, %u\n", header->size, archive_size);

        if (header->name[0U] == '/') { // Special member
            next_byte += archive_size;
            continue;
        }

        if (*(u16*)next_byte == 0U) {
            struct import_header* import_header = (struct import_header*)next_byte;
            char* import_name = (char*)next_byte + sizeof(*import_header);

            size_t len = 0U;
            StringCchLengthA((char*)import_name, 256U, &len);
            print("IMPORT NAME: %s\n", import_name);

            char* dll_name = import_name + len + 1U;
            print("DLL NAME: %s\n", dll_name);
        } else {
            read_COFF(next_byte);
        }
        next_byte += archive_size;
    }
}

struct PE_headers {
    IMAGE_DOS_HEADER dos_header;
    u8 dos_stub[88U];
    u32 nt_signature;
    IMAGE_FILE_HEADER img_header;
    IMAGE_OPTIONAL_HEADER64 opt_header;
};

#define SECTION_ALIGNMENT   4096U  // default values for optional header
#define FILE_ALIGNMENT      512U      // default values for optional header

static void write_exe_headers(u8* buffer) {
    static struct PE_headers PE_headers = {
        .dos_header = {
            .e_magic    = IMAGE_DOS_SIGNATURE,
            .e_cblp     = 0x0U,
            .e_cp       = 0x0U,
            .e_crlc     = 0x0U,
            .e_cparhdr  = 0x0U,
            .e_minalloc = 0x0U,
            .e_maxalloc = 0x0U,
            .e_ss       = 0x0U,
            .e_sp       = 0x0U,
            .e_csum     = 0x0U,
            .e_ip       = 0x0U,
            .e_cs       = 0x0U,
            .e_lfarlc   = 0x0U,
            .e_ovno     = 0x0U,
            .e_res      = { 0x0 },
            .e_oemid    = 0x0U,
            .e_oeminfo  = 0x0U,
            .e_res2     = { 0x0 },
            .e_lfanew   = offsetof(struct PE_headers, nt_signature),
        },
        .dos_stub = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 
            0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
            0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, 
            0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
            0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 
            0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
            0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 
            0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
            0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        .nt_signature = IMAGE_NT_SIGNATURE,
        .img_header = {
            .Machine                = IMAGE_FILE_MACHINE_AMD64,
            .NumberOfSections       = 0U,
            .TimeDateStamp          = 0U,
            .PointerToSymbolTable   = 0U,
            .NumberOfSymbols        = 0U,
            .SizeOfOptionalHeader   = sizeof(PE_headers.opt_header),
            .Characteristics        = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE,
        },
        .opt_header = {
            .Magic                          = IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            .MajorLinkerVersion             = 0U,
            .MinorLinkerVersion             = 1U,
            .SizeOfCode                     = 0U,
            .SizeOfInitializedData          = 0U,
            .SizeOfUninitializedData        = 0U,
            .AddressOfEntryPoint            = 0U,
            .BaseOfCode                     = 0U,
            .ImageBase                      = 0x00400000U,  // default value for Windows NT/2000/XP/95/98/ME
            .SectionAlignment               = SECTION_ALIGNMENT,
            .FileAlignment                  = FILE_ALIGNMENT,
            .MajorOperatingSystemVersion    = 6U,
            .MinorOperatingSystemVersion    = 0U,
            .MajorImageVersion              = 0U,
            .MinorImageVersion              = 0U,
            .MajorSubsystemVersion          = 6U,
            .MinorSubsystemVersion          = 0U,
            .Win32VersionValue              = 0U,
            .SizeOfImage                    = 0U,           // must be aligned on section alignment
            .SizeOfHeaders                  = 0U,           // must be aligned on file alignment
            .CheckSum                       = 0U,
            .Subsystem                      = IMAGE_SUBSYSTEM_WINDOWS_CUI,
            .DllCharacteristics             = 0U,
            .SizeOfStackReserve             = 4096U * 10U,  // Arbitrary values
            .SizeOfStackCommit              = 4096U * 10U,  // Arbitrary values
            .SizeOfHeapReserve              = 4096U * 10U,  // Arbitrary values
            .SizeOfHeapCommit               = 4096U * 10U,  // Arbitrary values
            .LoaderFlags = 0U,
            .NumberOfRvaAndSizes = 0U,
            .DataDirectory = { 0x0 },
        },
    };

    FILETIME filetime = { 0U };
    GetSystemTimeAsFileTime(&filetime);

    PE_headers.img_header.TimeDateStamp     = filetime.dwLowDateTime;

    mem_copy(&PE_headers, buffer, sizeof(PE_headers));
}

static u8 test_main[] = { 0x33, 0xc0, 0xc3 };

static void write_text_section(IMAGE_SECTION_HEADER* section_table, u16* section_count) {
    IMAGE_SECTION_HEADER* text_section_header = &section_table[*section_count];
    mem_copy(".text", text_section_header->Name, 6U);

    text_section_header->VirtualAddress         = 0x0U;
    text_section_header->PointerToRawData       = 0x0U;
    text_section_header->PointerToRelocations   = 0x0U;
    text_section_header->PointerToLinenumbers   = 0x0U;
    text_section_header->NumberOfRelocations    = 0U;
    text_section_header->NumberOfLinenumbers    = 0U;
    text_section_header->Characteristics        = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    (*section_count)++;
}

int mainCRTStartup(void) {
    char* args_string = VirtualAlloc(NULL, 4096U, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    char** argv = VirtualAlloc(NULL, 4096U, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    argv[0U] = args_string;
    u32 argc = 1U;

    {
        LPSTR args = GetCommandLineA();

        for (u32 char_index = 0U; *(args + char_index) != '\0'; char_index++) {
            char c = *(args + char_index);
            if (c == ' ') {
                args_string[char_index] = '\0';
                argv[argc] = &args_string[char_index + 1U];
                argc++;
            } else 
            {
                args_string[char_index] = c;
            }
        }
    }


    char* libs[64U] = { 0U };
    u32 libs_count = 0U;
    char* lib_paths = VirtualAlloc(NULL, 4096U, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    {
        DWORD ret = GetEnvironmentVariableA("LIB", (char*)lib_paths, 4096U);
        if (ret != 0U) {
            print("LIB: %s\n", lib_paths);
            libs[0U] = lib_paths;

            for (u32 char_index = 0U; *(lib_paths + char_index) != '\0'; char_index++) {
                char c = *(lib_paths + char_index);
                if (c == ';') {
                    libs_count++;
                    lib_paths[char_index] = '\0';
                    libs[libs_count] = &lib_paths[char_index + 1U];
                }
            }

            if (libs[libs_count][0U] != '\0') {
                libs_count++;
            }
        }
    }

    for (u32 index = 0U; index < libs_count; index++) {
        print("LIB %u: %s\n", index, libs[index]);
    }

    char* filepath = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    for (u32 arg_index = 1U; arg_index < argc; arg_index++) {
        // NtCreateFile(".\build\main.obj", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0U, NULL);
        print("ARG %u: %s\n", arg_index, argv[arg_index]);

        u32 pathsize = SearchPathA(".", argv[arg_index], NULL, 4096U, filepath, NULL);
        if (pathsize == 0U) {
            for (u32 lib_index = 0U; lib_index < libs_count && pathsize == 0U; lib_index++) {
                pathsize = SearchPathA(libs[lib_index], argv[arg_index], NULL, 4096U, filepath, NULL);
            }
        }

        if (pathsize != 0U) {
            print("FOUND: %s\n", filepath);
        } else {
            print("COULD NOT FOUND %s\n", argv[arg_index]);
            continue;
        }

        HANDLE file = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0U, NULL);

        if (!file && file != INVALID_HANDLE_VALUE) {
            continue;
        }

        LARGE_INTEGER file_size = { 0 };
        GetFileSizeEx(file, &file_size);

        u8* buffer = VirtualAlloc(NULL, file_size.LowPart, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        DWORD bread = 0U;
        ReadFile(file, buffer, file_size.LowPart, &bread, NULL);

        if (*(u64*)buffer == lib_signature) {
            read_lib(buffer + sizeof(lib_signature));
        } else {
            read_COFF(buffer);
        }
        CloseHandle(file);
        VirtualFree(buffer, 0U, MEM_RELEASE);
    }

    // TODO: Reserve a huge block and commit when we need more memory
    u8* exe_buffer = VirtualAlloc(NULL, 4096U * 10U, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    HANDLE output_file = CreateFile("./test.exe", GENERIC_WRITE, 0U, NULL, CREATE_ALWAYS, 0U, NULL);

    __debugbreak();

    struct PE_headers* headers = (struct PE_headers*)exe_buffer;
    IMAGE_SECTION_HEADER* section_table = (IMAGE_SECTION_HEADER*)(exe_buffer + sizeof(*headers));
    u16 section_count = 0U;

    // dont write section count to img header
    write_exe_headers(exe_buffer);

    // Write section headers
    write_text_section(section_table, &section_count);

    // Write section bodies
    // TODO: index per section ?
    u32 code_size = sizeof(test_main);
    u32 headers_size = ALIGN(sizeof(*headers) + (sizeof(IMAGE_SECTION_HEADER) * section_count), FILE_ALIGNMENT);
    mem_copy(test_main, (void*)(exe_buffer + headers_size), code_size);
    section_table[0U].SizeOfRawData     = ALIGN(code_size, FILE_ALIGNMENT);
    section_table[0U].Misc.VirtualSize  = ALIGN(code_size, SECTION_ALIGNMENT);

    // Set sections pointer to raw data
    _Static_assert(FILE_ALIGNMENT < SECTION_ALIGNMENT, "section alignment must greater or equal to file alignment in order to align headers_size on section alignment");
    u32 file_offset = headers_size;
    u32 virtual_offset = ALIGN(headers_size, SECTION_ALIGNMENT);
    IMAGE_SECTION_HEADER* cur_section = section_table;
    for (u32 section_index = 0U; section_index < section_count; section_index++, cur_section++) {
        cur_section->PointerToRawData = file_offset;
        cur_section->VirtualAddress = virtual_offset;

        ASSERT(cur_section->SizeOfRawData == ALIGN(cur_section->SizeOfRawData, FILE_ALIGNMENT));
        ASSERT(cur_section->Misc.VirtualSize == ALIGN(cur_section->Misc.VirtualSize, SECTION_ALIGNMENT));
        file_offset += cur_section->SizeOfRawData;
        virtual_offset += cur_section->Misc.VirtualSize;
    }

    // Fill remaining header informations
    headers->img_header.NumberOfSections   = section_count;

    headers->opt_header.SizeOfHeaders       = headers_size; // aligned on file alignment
    headers->opt_header.AddressOfEntryPoint = section_table[0U].VirtualAddress;
    headers->opt_header.BaseOfCode          = section_table[0U].PointerToRawData;
    headers->opt_header.SizeOfCode          = section_table[0U].SizeOfRawData;
    headers->opt_header.SizeOfImage         = ALIGN(section_table[section_count - 1U].VirtualAddress + section_table[section_count - 1U].Misc.VirtualSize, SECTION_ALIGNMENT);

    DWORD bwrite = 0U;
    WriteFile(output_file, exe_buffer, headers->opt_header.SizeOfImage, &bwrite, NULL);
    ASSERT(bwrite == headers->opt_header.SizeOfImage);

    CloseHandle(output_file);

    __debugbreak();

    VirtualFree(exe_buffer, 0U, MEM_RELEASE);
    VirtualFree(filepath, 0U, MEM_RELEASE);
    VirtualFree(lib_paths, 0U, MEM_RELEASE);
    VirtualFree(argv, 0U, MEM_RELEASE);
    VirtualFree(args_string, 0U, MEM_RELEASE);

    return 0;
}
