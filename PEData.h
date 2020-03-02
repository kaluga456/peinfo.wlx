#ifndef PEDataH
#define PEDataH
//---------------------------------------------------------------------------
//file structure
//- dos header
//- PE signature (PE\0\0)
//- coff header
//- optional header 32/64
//---------------------------------------------------------------------------
class TPEData
{
public:
    TPEData();
    ~TPEData();

    //init
    void Reset();
    bool ParseFile(LPCTSTR file_name);

    LPCTSTR GetErrorString();


    const LARGE_INTEGER& GetFileSize() const {return FileSize;}

    //data
    const IMAGE_DOS_HEADER* GetDosHeader() const {return DosHeader;}
    const IMAGE_NT_HEADERS32* GetNTHeaders32() const {return NTHeaders32;}
    const IMAGE_NT_HEADERS64* GetNTHeaders64() const {return NTHeaders64;}
    const IMAGE_FILE_HEADER* GetFileHeader() const {return FileHeader;}
    const IMAGE_OPTIONAL_HEADER32* GetOptHeader32() const {return OptHeader32;}
    const IMAGE_OPTIONAL_HEADER64* GetOptHeader64() const {return OptHeader64;}
    const IMAGE_DATA_DIRECTORY* GetImageDirectoryEntry(int index) const;
    const IMAGE_SECTION_HEADER* GetSectionHeader(int index) const;
    const IMAGE_EXPORT_DIRECTORY* GetExportDirectory() const {return ExportDirectory;}

    //access
    const BYTE* GetFilePointer(DWORD rva) const;

    //sections
    const IMAGE_EXPORT_DIRECTORY* ExportDirectory;
    const DWORD* ExportFunctions;
    const DWORD* ExportNames;
    const WORD*  ExportNameOrdinals;

private:
    static const int MAX_SECTION_COUNT = 96;

    //file
    HANDLE File;
    HANDLE FileMap;
    const void* FileData;
    LARGE_INTEGER FileSize;
    void Close();

    //data
    const IMAGE_DOS_HEADER* DosHeader;
    const IMAGE_NT_HEADERS32* NTHeaders32;
    const IMAGE_NT_HEADERS64* NTHeaders64;
    const IMAGE_FILE_HEADER* FileHeader;
    const IMAGE_OPTIONAL_HEADER32* OptHeader32;
    const IMAGE_OPTIONAL_HEADER64* OptHeader64;
    const IMAGE_SECTION_HEADER* SectionHeaders[MAX_SECTION_COUNT];
    DWORD SectionAlignment;

    //error
    DWORD ErrorCode; //system error code
    LPCTSTR ErrorString; //app error string
    static const int ERROR_BUFFER_SIZE = 2048;
    TCHAR ErrorBuffer[ERROR_BUFFER_SIZE];
    void SetError(DWORD error_code, LPCTSTR error_string = _T("")); //for system error
    void SetError(LPCTSTR error_string); //for app error

    //pointers
    const BYTE* GetNtHeaders() const;
    DWORD GetSectionAlignment() const;
    const IMAGE_SECTION_HEADER* GetSectionByAddress(DWORD rva) const;

    //read
    const void* CurrentPos;
    void SetPos(DWORD pos);
    const BYTE* ReadRawData(DWORD size, bool move_pos = true);
    template<typename T> const T* ReadData(bool move_pos = true)
    {
        const BYTE* current_pos = reinterpret_cast<const BYTE*>(CurrentPos);
        if(current_pos - reinterpret_cast<const BYTE*>(FileData) + sizeof(T) > FileSize.LowPart) PEDataException(_T("Unexpected end of file"));
        const T* result = reinterpret_cast<const T*>(CurrentPos);
        if(move_pos) CurrentPos = current_pos + sizeof(T);
        return result;
    }
};
//---------------------------------------------------------------------------
#endif
