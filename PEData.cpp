#include "peinfo_pch.h"
#pragma hdrstop
#include "PEData.h"

static DWORD AlignInteger(DWORD value, DWORD alignment)
{
    if(0 == value || 0 == alignment) return value;
    if(0 == value % alignment) return value;
    return (value / alignment + 1) * alignment;
}

class PEDataException
{
public:
    DWORD ErrorCode;
    LPCTSTR ErrorString;
    explicit PEDataException(DWORD error_code, LPCTSTR error_string = _T("")) : ErrorCode(error_code), ErrorString(error_string) {}
    explicit PEDataException(LPCTSTR error_string) : ErrorCode(ERROR_SUCCESS), ErrorString(error_string) {}
};

TPEData::TPEData() : File(INVALID_HANDLE_VALUE)
{
    Reset();
}
TPEData::~TPEData()
{
    Close();
}
void TPEData::Close()
{
    //close handles
    if(FileData)
    {
        ::UnmapViewOfFile(FileData);
        FileData = NULL;
    }
    if(File != NULL)
    {
        ::CloseHandle(FileMap); 
        FileMap = NULL;
    }
    if(File != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(File);
        File = INVALID_HANDLE_VALUE;
    }

    //data
    DosHeader = NULL;
    NTHeaders32 = NULL;
    NTHeaders64 = NULL;
    FileHeader = NULL;
    OptHeader32 = NULL;
    OptHeader64 = NULL;
    ExportDirectory = NULL;
    ::ZeroMemory(SectionHeaders, MAX_SECTION_COUNT * sizeof(void*));
}
void TPEData::Reset()
{
    Close();
    ErrorCode = ERROR_SUCCESS;
    ErrorString = _T("No PE file defined");
}
void TPEData::SetError(DWORD error_code, LPCTSTR error_string /*= _T("")*/)
{
    ErrorCode = error_code;
    ErrorString = error_string;
}
void TPEData::SetError(LPCTSTR error_string)
{
    ErrorCode = ERROR_SUCCESS;
    ErrorString = error_string;
}
LPCTSTR TPEData::GetErrorString()
{
    //TODO: combine system error string with app error string
    if(ERROR_SUCCESS == ErrorCode) return ErrorString;
    DWORD error_string_size = ::FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
                                              FORMAT_MESSAGE_IGNORE_INSERTS, 
                                              NULL, 
                                              ErrorCode, 
                                              MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //default language
                                              ErrorBuffer, 
                                              ERROR_BUFFER_SIZE, 
                                              NULL);

    if(error_string_size < 2) return _T("Undefined error");

    //ok
    error_string_size -= 2; //exclude trailing "\r\n" symbols
    ErrorBuffer[error_string_size] = 0; 
    return ErrorBuffer;
}
const IMAGE_DATA_DIRECTORY* TPEData::GetImageDirectoryEntry(int index) const
{
    if(index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)  return NULL;
    if(OptHeader32) return &OptHeader32->DataDirectory[index];
    if(OptHeader64) return &OptHeader64->DataDirectory[index];
    return NULL;
}
const IMAGE_SECTION_HEADER* TPEData::GetSectionHeader(int index) const
{
    return (index < MAX_SECTION_COUNT) ? SectionHeaders[index] : NULL;
}
const BYTE* TPEData::GetNtHeaders() const
{
    if(NTHeaders32) return reinterpret_cast<const BYTE*>(NTHeaders32);
    if(NTHeaders64) return reinterpret_cast<const BYTE*>(NTHeaders64);
    return NULL;
}
DWORD TPEData::GetSectionAlignment() const
{
    if(OptHeader32) return OptHeader32->SectionAlignment;
    if(OptHeader64) return OptHeader64->SectionAlignment;
    return 0;
}
const IMAGE_SECTION_HEADER* TPEData::GetSectionByAddress(DWORD rva) const
{
    if(NULL == FileHeader) return NULL;
    const DWORD section_align = GetSectionAlignment();
    for(int i = 0; i < FileHeader->NumberOfSections; ++i)
    {
        const IMAGE_SECTION_HEADER* section_header = GetSectionHeader(i);
        if(NULL == section_header) continue;
        const DWORD section_size = AlignInteger(section_header->Misc.VirtualSize, section_align);
        if (section_header->VirtualAddress <= rva && rva < section_header->VirtualAddress + section_size) return section_header;
    }
    return NULL;
}
const BYTE* TPEData::GetFilePointer(DWORD rva) const
{
    const BYTE* file_data = reinterpret_cast<const BYTE*>(FileData);
    if(NULL == FileHeader) return NULL;
    const IMAGE_SECTION_HEADER* section_header = GetSectionByAddress(rva);
    if(NULL == section_header) return file_data + rva; //relative to file base
    return file_data + section_header->PointerToRawData - section_header->VirtualAddress + rva; //relative to section base
}
void TPEData::SetPos(DWORD pos)
{
    if(pos >= FileSize.LowPart) throw PEDataException(_T("Unexpected end of file"));
    CurrentPos = reinterpret_cast<const BYTE*>(FileData) + pos;
}
const BYTE* TPEData::ReadRawData(DWORD size, bool move_pos /*= true*/)
{
    const BYTE* current_pos = reinterpret_cast<const BYTE*>(CurrentPos);
    if(current_pos - reinterpret_cast<const BYTE*>(FileData) + size > FileSize.LowPart) throw PEDataException(_T("Unexpected end of file"));
    const BYTE* result = reinterpret_cast<const BYTE*>(CurrentPos);
    if(move_pos) CurrentPos = current_pos + size;
    return result;
}
bool TPEData::ParseFile(LPCTSTR file_name)
{
    try
    {
        Reset();
        if(NULL == file_name) throw PEDataException(_T("No PE file defined"));

        //open file
        File = CreateFile(file_name, GENERIC_READ, 0, NULL, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, NULL);
        if(INVALID_HANDLE_VALUE == File) throw PEDataException(::GetLastError(), _T("Unable to open file"));

        //file size check
        if(FALSE == GetFileSizeEx(File, &FileSize)) throw PEDataException(::GetLastError(), _T("Unable to determine file size"));
        if(FileSize.HighPart) throw PEDataException(_T("File is too big")); //4GB max
        if(FileSize.LowPart < sizeof(IMAGE_DOS_HEADER)) throw PEDataException(_T("File is too small"));

        //map file
        FileMap = CreateFileMapping(File, NULL, PAGE_READONLY, 0, 0, NULL);
        if(NULL == FileMap) throw PEDataException(::GetLastError(), _T("Unable to create file mapping"));
        FileData = MapViewOfFile(FileMap, FILE_MAP_READ, 0, 0, 0);
        if(NULL == FileData) throw PEDataException(::GetLastError(), _T("Unable to map file"));
        CurrentPos = FileData;

        //read DOS header
        DosHeader = ReadData<IMAGE_DOS_HEADER>(false);
        if(DosHeader->e_magic != IMAGE_DOS_SIGNATURE) throw PEDataException(_T("Reading DOS header failed"));

        //read PE signarute
        SetPos(DosHeader->e_lfanew);
        const DWORD* pe_signature = ReadData<DWORD>();
        if(*pe_signature != IMAGE_NT_SIGNATURE) throw PEDataException(_T("Reading PE signature failed"));
 
        //read COFF header
        FileHeader = ReadData<IMAGE_FILE_HEADER>();

        //detect optional header type
        bool is64 = false;
        const WORD* opt_header_magic = ReadData<WORD>(false);
        if(IMAGE_NT_OPTIONAL_HDR32_MAGIC == *opt_header_magic) is64 = false;
        else if(IMAGE_NT_OPTIONAL_HDR64_MAGIC == *opt_header_magic) is64 = true;
        else throw PEDataException(_T("Optional header not supporrted"));

        //NT headers
        if(is64) NTHeaders64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pe_signature);
        else NTHeaders32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(pe_signature);

        //read optional header
        if(is64) OptHeader64 = ReadData<IMAGE_OPTIONAL_HEADER64>();
        else OptHeader32 = ReadData<IMAGE_OPTIONAL_HEADER32>();

        //read section headers
        const WORD section_count = FileHeader->NumberOfSections < MAX_SECTION_COUNT ? FileHeader->NumberOfSections : MAX_SECTION_COUNT;
        for(int section_index = 0; section_index < section_count; ++section_index)
        {
            SectionHeaders[section_index] = ReadData<IMAGE_SECTION_HEADER>();
        }

        //TODO: read export table
        const IMAGE_DATA_DIRECTORY* export_ide = GetImageDirectoryEntry(IMAGE_DIRECTORY_ENTRY_EXPORT);
        if(export_ide->VirtualAddress && export_ide->Size)
        {
            ExportDirectory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(GetFilePointer(export_ide->VirtualAddress));
            ExportFunctions = reinterpret_cast<const DWORD*>(GetFilePointer(ExportDirectory->AddressOfFunctions));
            ExportNames = reinterpret_cast<const DWORD*>(GetFilePointer(ExportDirectory->AddressOfNames));
            ExportNameOrdinals = reinterpret_cast<const WORD*>(GetFilePointer(ExportDirectory->AddressOfNameOrdinals));
        }

        //IMAGE_EXPORT_DIRECTORY
        //DWORD   Characteristics;
        //DWORD   TimeDateStamp;
        //WORD    MajorVersion;
        //WORD    MinorVersion;
        //DWORD   Name;
        //DWORD   Base;
        //DWORD   NumberOfFunctions;
        //DWORD   NumberOfNames;
        //DWORD   AddressOfFunctions;     // RVA from base of image
        //DWORD   AddressOfNames;         // RVA from base of image
        //DWORD   AddressOfNameOrdinals;  // RVA from base of image

        //TODO: read sections


        SetError(_T(""));
        return true;
    }
    catch(PEDataException& exception)
    {
        SetError(exception.ErrorCode, exception.ErrorString);
    }
    catch(...)
    {
        SetError(_T("Undefined error"));
    }

    Close();
    return false;
}
