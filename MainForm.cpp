//---------------------------------------------------------------------------
#include "peinfo_pch.h"
#pragma hdrstop
#include "PEData.h"
#include "Options.h"
#include "MainForm.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma link "cxControls"
#pragma link "cxCustomData"
#pragma link "cxGraphics"
#pragma link "cxInplaceContainer"
#pragma link "cxLookAndFeelPainters"
#pragma link "cxLookAndFeels"
#pragma link "cxStyles"
#pragma link "cxTL"
#pragma link "cxTLdxBarBuiltInMenu"
#pragma link "cxTextEdit"
#pragma resource "*.dfm"

TForm1 *Form1;
//---------------------------------------------------------------------------
//TTabSheet::Tag values
enum
{
  TAB_EMPTY = 0,
  TAB_OK = 1
};
//---------------------------------------------------------------------------
//TTabSheet::Tag values
enum
{
  COL_FIELD_INDEX = 0,
  COL_VALUE_INDEX = 1,
  COL_DESCR_INDEX = 2
};
//---------------------------------------------------------------------------
static void CopyToClipboard(HWND hwnd, LPCTSTR text)
{
  if(NULL == text) text = _T("");

  if(FALSE == ::OpenClipboard(hwnd))
  {
    //TODO: handle error
    return;
  }
  if(FALSE == ::EmptyClipboard())
  {
    ::CloseClipboard();
    //TODO: handle error
    return;
  }

  //allocate a global memory object for the text
  const int data_size = (::wcslen(text) + 1) * sizeof(TCHAR);
  const HANDLE hmem = ::GlobalAlloc(GMEM_MOVEABLE, data_size);
  if(NULL == hmem)
  {
    ::CloseClipboard();
    //TODO: handle error
    return;
  }

  //lock the handle and copy the text to the buffer
  void* buffer = ::GlobalLock(hmem);
  if(NULL == buffer)
  {
    ::CloseClipboard();
    //TODO: handle error
    return;
  }
  memcpy(buffer, text, data_size);
  ::GlobalUnlock(hmem);

  HANDLE handle = ::SetClipboardData(CF_UNICODETEXT, hmem);
  if(NULL == handle)
  {
    //TODO: handle error
  }
  ::CloseClipboard();
}
//---------------------------------------------------------------------------
//values to string
//---------------------------------------------------------------------------
String GetDecString(UINT Value)
{
  return String().sprintf(L"%u", Value);
}
//---------------------------------------------------------------------------
template<typename T> String GetHexString(T Value)
{
  const wchar_t* format_str = NULL;
  switch(sizeof(T))
  {
  case 1: format_str = L"0x%02X"; break;
  case 2: format_str = L"0x%04X"; break;
  case 4: format_str = L"0x%08X"; break;
  case 8: format_str = L"0x%016X"; break;
  default:
    assert(0);
    format_str = L"0x%X";
  }
  return String().sprintf(format_str, Value);
}
//---------------------------------------------------------------------------
String GetHexString(const WORD* Value, int Size)
{
  String result;
  for(int i = 0; i < Size; ++i) result += String().sprintf(L"%04X ", Value[i]);
  return result;
}
//---------------------------------------------------------------------------
String GetDateTimeString(time_t value)
{
  if(0 == value) return GetHexString(value);
  const int buff_size = 24;
  static TCHAR buff[buff_size];
  const struct tm* tms = ::gmtime(&value);
  if(NULL == tms) return L"";
  _tcsftime(buff, buff_size, _T("%d.%m.%y %H:%M:%S UTC"), tms);
  return buff;
}
//---------------------------------------------------------------------------
String GetMachineTypeString(WORD value)
{
  switch(value)
  {
  case IMAGE_FILE_MACHINE_UNKNOWN: return _T("Unknown (assumed to be applicable to any machine type)");
  case IMAGE_FILE_MACHINE_AM33: return _T("Matsushita AM33");
  case IMAGE_FILE_MACHINE_AMD64: return _T("x64");
  case IMAGE_FILE_MACHINE_ARM: return _T("ARM little endian");
  case 0xaa64: return _T("ARM64 little endian"); //IMAGE_FILE_MACHINE_ARM64
  case 0x01c4: return _T("ARM Thumb-2 little endian"); //IMAGE_FILE_MACHINE_ARMNT
  case IMAGE_FILE_MACHINE_EBC: return _T("EFI byte code");
  case IMAGE_FILE_MACHINE_I386: return _T("Intel 386 or later processors and compatible processors");
  case IMAGE_FILE_MACHINE_IA64: return _T("Intel Itanium processor family");
  case IMAGE_FILE_MACHINE_M32R: return _T("Mitsubishi M32R little endian");
  case IMAGE_FILE_MACHINE_MIPS16: return _T("MIPS16");
  case IMAGE_FILE_MACHINE_MIPSFPU: return _T("MIPS with FPU");
  case IMAGE_FILE_MACHINE_MIPSFPU16: return _T("MIPS16 with FPU");
  case IMAGE_FILE_MACHINE_POWERPC: return _T("Power PC little endian");
  case IMAGE_FILE_MACHINE_POWERPCFP: return _T("Power PC with floating point support");
  case IMAGE_FILE_MACHINE_R4000: return _T("MIPS little endian");
  case 0x5032: return _T("RISC-V 32-bit address space"); //IMAGE_FILE_MACHINE_RISCV32
  case 0x5064: return _T("RISC-V 64-bit address space"); //IMAGE_FILE_MACHINE_RISCV64
  case 0x5128: return _T("RISC-V 128-bit address space"); //IMAGE_FILE_MACHINE_RISCV128
  case IMAGE_FILE_MACHINE_SH3: return _T("Hitachi SH3");
  case IMAGE_FILE_MACHINE_SH3DSP: return _T("Hitachi SH3 DSP");
  case IMAGE_FILE_MACHINE_SH4: return _T("Hitachi SH4");
  case IMAGE_FILE_MACHINE_SH5: return _T("Hitachi SH5");
  case IMAGE_FILE_MACHINE_THUMB: return _T("Thumb");
  case IMAGE_FILE_MACHINE_WCEMIPSV2: return _T("MIPS little-endian WCE v2 ");
  }
  return _T("Unknown machine");
}
//---------------------------------------------------------------------------
//TcxUpdate
//---------------------------------------------------------------------------
class TcxUpdate
{
private:
	TcxTreeList* TreeList;

public:
  explicit __fastcall TcxUpdate(TcxTreeList* tree_list) : TreeList(tree_list) {TreeList->BeginUpdate();}
	__fastcall ~TcxUpdate() {TreeList->EndUpdate();}
};
//---------------------------------------------------------------------------
//TForm1
//---------------------------------------------------------------------------
__fastcall TForm1::TForm1(TComponent* Owner, String full_file_name, const TPEData& ped) : TForm(Owner), FullFileName(full_file_name), PEData(ped)
{
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FormCreate(TObject *Sender)
{
  //TSOptions
  LBAppInfo->Caption = APP_NAME L"  (Build: " APP_BUILD L")";
  CBDetectByContent->Enabled = false;

  const int last_tab = Options.ReadInt(L"LastTab");
  PCMain->ActivePageIndex = last_tab < PCMain->PageCount ? last_tab : 0;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::ReadNodeState(String reg_key, TcxTreeListNode* node)
{
  if(NULL == node) return;
  Options.ReadBool(reg_key, true) ? node->Expand(true) : node->Collapse(true);
}
//---------------------------------------------------------------------------
void __fastcall TForm1::WriteNodeState(String reg_key, TcxTreeListNode* node)
{
  if(NULL == node) return;
  if(node->HasChildren) Options.WriteBool(reg_key, node->Expanded);
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FormDestroy(TObject *Sender)
{
  Options.WriteInt(L"LastTab", PCMain->ActivePageIndex);

  //TSGeneral
  WriteNodeState(L"TNFileSystem", TNFileSystem);
  WriteNodeState(L"TNVersionInfo", TNVersionInfo);

  //TSHeaders
  WriteNodeState(L"TNDosHeader", TNDosHeader);
  WriteNodeState(L"TNPEHeader", TNPEHeader);
  WriteNodeState(L"TNOptHeader", TNOptHeader);
  WriteNodeState(L"TNDataDir", TNDataDir);
  WriteNodeState(L"TNSections", TNSections);

  //TSDependency
  //TSImports

  //TSExports
  WriteNodeState(L"TNExportDir", TNExportDir);
  WriteNodeState(L"TNExports", TNExports);

  //TSManifest
  //TSDump
  //TSOptions
}
//---------------------------------------------------------------------------
void __fastcall TForm1::AddNode(TcxTreeListNode* root_node, String field, String value, String descr /*= L""*/)
{
  TcxTreeListNode* node = root_node->AddChild();
  node->Values[COL_FIELD_INDEX] = field;
  node->Values[COL_VALUE_INDEX] = value;
  node->Values[COL_DESCR_INDEX] = descr;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::InitTSGeneral()
{
  TcxUpdate tree_list_update(TLGeneral);

  TNFileSystem = TLGeneral->Add();
  TNFileSystem->Values[ColGeneralField->ItemIndex] = String(L"File system info");
  TNVersionInfo = TLGeneral->Add();
  TNVersionInfo->Values[ColGeneralField->ItemIndex] = String(L"Version info");

  AddNode(TNFileSystem, L"Full file name", FullFileName);
  AddNode(TNFileSystem, L"File size", GetDecString(PEData.GetFileSize().LowPart) + L" bytes");

  ReadNodeState(L"TNFileSystem", TNFileSystem);
  ReadNodeState(L"TNVersionInfo", TNVersionInfo);
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FillDataDirValue(int Index, String Field, String Descr /*= L""*/)
{
  TcxTreeListNode* node = TNDataDir->AddChild();
  const IMAGE_DATA_DIRECTORY* idd = PEData.GetImageDirectoryEntry(Index);
  if(NULL == idd) return;
  node->Values[COL_FIELD_INDEX] = Field;
  node->Values[ColHeadersValue->ItemIndex] = GetHexString(idd->VirtualAddress) + L":" + GetHexString(idd->Size);
  node->Values[ColHeadersDescr->ItemIndex] = Descr;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::InitTSHeaders()
{
  TcxUpdate tree_list_update(TLHeaders);

  //top nodes
  TNDosHeader = TLHeaders->Add();
  TNDosHeader->Values[COL_FIELD_INDEX] = String(L"DOS Header");
  TNDosHeader->Values[COL_VALUE_INDEX] = String(L"IMAGE_DOS_HEADER");
  TNPEHeader = TLHeaders->Add();
  TNPEHeader->Values[COL_FIELD_INDEX] = String(L"COFF Header");
  TNPEHeader->Values[COL_VALUE_INDEX] = String(L"IMAGE_FILE_HEADER");
  TNOptHeader = TLHeaders->Add();
  TNOptHeader->Values[COL_FIELD_INDEX] = String(L"Optional Header");
  TNDataDir = TLHeaders->Add();
  TNDataDir->Values[COL_FIELD_INDEX] = String(L"Data Directory");
  TNDataDir->Values[COL_VALUE_INDEX] = String(L"IMAGE_DATA_DIRECTORY");
  TNSections = TLHeaders->Add();
  TNSections->Values[COL_FIELD_INDEX] = String(L"Sections");
  TNSections->Values[COL_VALUE_INDEX] = String(L"IMAGE_SECTION_HEADER");

  const IMAGE_DOS_HEADER* dos_header = PEData.GetDosHeader();
  if(dos_header)
  {
    //NOTE: _IMAGE_DOS_HEADER structure:
    //WORD   e_magic;                     // Magic number
    //WORD   e_cblp;                      // Bytes on last page of file
    //WORD   e_cp;                        // Pages in file
    //WORD   e_crlc;                      // Relocations
    //WORD   e_cparhdr;                   // Size of header in paragraphs
    //WORD   e_minalloc;                  // Minimum extra paragraphs needed
    //WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    //WORD   e_ss;                        // Initial (relative) SS value
    //WORD   e_sp;                        // Initial SP value
    //WORD   e_csum;                      // Checksum
    //WORD   e_ip;                        // Initial IP value
    //WORD   e_cs;                        // Initial (relative) CS value
    //WORD   e_lfarlc;                    // File address of relocation table
    //WORD   e_ovno;                      // Overlay number
    //WORD   e_res[4];                    // Reserved words
    //WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    //WORD   e_oeminfo;                   // OEM information; e_oemid specific
    //WORD   e_res2[10];                  // Reserved words
    //LONG   e_lfanew;                    // File address of new exe header

    AddNode(TNDosHeader, L"Magic number", GetHexString(dos_header->e_magic));
    AddNode(TNDosHeader, L"Bytes on last page of file", GetDecString(dos_header->e_cblp));
    AddNode(TNDosHeader, L"Pages in file", GetDecString(dos_header->e_cp));
    AddNode(TNDosHeader, L"Relocations", GetHexString(dos_header->e_crlc));
    AddNode(TNDosHeader, L"Size of header in paragraphs", GetDecString(dos_header->e_cparhdr));
    AddNode(TNDosHeader, L"Minimum extra paragraphs needed", GetDecString(dos_header->e_minalloc));
    AddNode(TNDosHeader, L"Maximum extra paragraphs needed", GetDecString(dos_header->e_maxalloc));
    AddNode(TNDosHeader, L"Initial (relative) SS value", GetHexString(dos_header->e_ss));
    AddNode(TNDosHeader, L"Initial SP value", GetHexString(dos_header->e_sp));
    AddNode(TNDosHeader, L"Checksum", GetHexString(dos_header->e_csum));
    AddNode(TNDosHeader, L"Initial IP value", GetHexString(dos_header->e_ip));
    AddNode(TNDosHeader, L"Initial (relative) CS value", GetHexString(dos_header->e_cs));
    AddNode(TNDosHeader, L"File address of relocation table", GetHexString(dos_header->e_lfarlc));
    AddNode(TNDosHeader, L"Overlay number", GetHexString(dos_header->e_ovno));
    AddNode(TNDosHeader, L"Reserved words (e_res[4])", GetHexString(dos_header->e_res, 4));
    AddNode(TNDosHeader, L"OEM identifier", GetHexString(dos_header->e_oemid));
    AddNode(TNDosHeader, L"OEM information", GetHexString(dos_header->e_oeminfo));
    AddNode(TNDosHeader, L"Reserved words (e_res2[10])", GetHexString(dos_header->e_res2, 10));
    AddNode(TNDosHeader, L"File address of new exe header", GetHexString(dos_header->e_lfanew));

    ReadNodeState(L"TNDosHeader", TNDosHeader);
  }

  const IMAGE_FILE_HEADER* file_header = PEData.GetFileHeader();
  if(file_header)
  {
    //NOTE: _IMAGE_FILE_HEADER structure:
    //WORD    Machine;
    //WORD    NumberOfSections;
    //DWORD   TimeDateStamp;
    //DWORD   PointerToSymbolTable;
    //DWORD   NumberOfSymbols;
    //WORD    SizeOfOptionalHeader;
    //WORD    Characteristics;

    AddNode(TNPEHeader, L"Machine", GetHexString(file_header->Machine), GetMachineTypeString(file_header->Machine));
    AddNode(TNPEHeader, L"NumberOfSections", GetDecString(file_header->NumberOfSections));
    AddNode(TNPEHeader, L"TimeDateStamp", ::GetDateTimeString(static_cast<const time_t>(file_header->TimeDateStamp)));
    AddNode(TNPEHeader, L"PointerToSymbolTable", GetHexString(file_header->PointerToSymbolTable));
    AddNode(TNPEHeader, L"NumberOfSymbols", GetDecString(file_header->NumberOfSymbols));
    AddNode(TNPEHeader, L"SizeOfOptionalHeader", GetDecString(file_header->SizeOfOptionalHeader));

    //TODO:
    //GetCoffCharsString(WORD value);
    AddNode(TNPEHeader, L"Characteristics", GetHexString(file_header->Characteristics));

    ReadNodeState(L"TNPEHeader", TNPEHeader);
  }

  const IMAGE_OPTIONAL_HEADER32* opt_header32 = PEData.GetOptHeader32();
  const IMAGE_OPTIONAL_HEADER64* opt_header64 = PEData.GetOptHeader64();
  if(opt_header32)
  {
    //NOTE: IMAGE_OPTIONAL_HEADER32 structure:
    //WORD    Magic;
    //BYTE    MajorLinkerVersion;
    //BYTE    MinorLinkerVersion;
    //DWORD   SizeOfCode;
    //DWORD   SizeOfInitializedData;
    //DWORD   SizeOfUninitializedData;
    //DWORD   AddressOfEntryPoint;
    //DWORD   BaseOfCode;
    //DWORD   BaseOfData;
    //DWORD   ImageBase;
    //DWORD   SectionAlignment;
    //DWORD   FileAlignment;
    //WORD    MajorOperatingSystemVersion;
    //WORD    MinorOperatingSystemVersion;
    //WORD    MajorImageVersion;
    //WORD    MinorImageVersion;
    //WORD    MajorSubsystemVersion;
    //WORD    MinorSubsystemVersion;
    //DWORD   Win32VersionValue;
    //DWORD   SizeOfImage;
    //DWORD   SizeOfHeaders;
    //DWORD   CheckSum;
    //WORD    Subsystem;
    //WORD    DllCharacteristics;
    //DWORD   SizeOfStackReserve;
    //DWORD   SizeOfStackCommit;
    //DWORD   SizeOfHeapReserve;
    //DWORD   SizeOfHeapCommit;
    //DWORD   LoaderFlags;
    //DWORD   NumberOfRvaAndSizes;
    //IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

    TNOptHeader->Values[ColHeadersDescr->ItemIndex] = String(L"IMAGE_OPTIONAL_HEADER32");
    AddNode(TNOptHeader, L"Magic", GetHexString(opt_header32->Magic), L"PE32");
    AddNode(TNOptHeader, L"MajorImageVersion", GetDecString(opt_header32->MajorImageVersion));
    AddNode(TNOptHeader, L"MinorLinkerVersion", GetDecString(opt_header32->MinorLinkerVersion));
    AddNode(TNOptHeader, L"SizeOfCode", GetDecString(opt_header32->SizeOfCode));
    AddNode(TNOptHeader, L"SizeOfInitializedData", GetDecString(opt_header32->SizeOfInitializedData));
    AddNode(TNOptHeader, L"SizeOfUninitializedData", GetDecString(opt_header32->SizeOfUninitializedData));
    AddNode(TNOptHeader, L"AddressOfEntryPoint", GetHexString(opt_header32->AddressOfEntryPoint));
    AddNode(TNOptHeader, L"BaseOfCode", GetHexString(opt_header32->BaseOfCode));
    AddNode(TNOptHeader, L"BaseOfData", GetHexString(opt_header32->BaseOfData));
    AddNode(TNOptHeader, L"ImageBase", GetHexString(opt_header32->ImageBase));
    AddNode(TNOptHeader, L"SectionAlignment", GetHexString(opt_header32->SectionAlignment));
    AddNode(TNOptHeader, L"FileAlignment", GetHexString(opt_header32->FileAlignment));
    AddNode(TNOptHeader, L"MajorOperatingSystemVersion", GetDecString(opt_header32->MajorOperatingSystemVersion));
    AddNode(TNOptHeader, L"MinorOperatingSystemVersion", GetDecString(opt_header32->MinorOperatingSystemVersion));
    AddNode(TNOptHeader, L"MajorImageVersion", GetDecString(opt_header32->MajorImageVersion));
    AddNode(TNOptHeader, L"MinorImageVersion", GetDecString(opt_header32->MinorImageVersion));
    AddNode(TNOptHeader, L"MajorSubsystemVersion", GetDecString(opt_header32->MajorSubsystemVersion));
    AddNode(TNOptHeader, L"MinorSubsystemVersion", GetDecString(opt_header32->MinorSubsystemVersion));
    AddNode(TNOptHeader, L"Win32VersionValue", GetDecString(opt_header32->Win32VersionValue), L"Reserved, must be zero");
    AddNode(TNOptHeader, L"SizeOfImage", GetDecString(opt_header32->SizeOfImage));
    AddNode(TNOptHeader, L"SizeOfHeaders", GetDecString(opt_header32->SizeOfHeaders));
    AddNode(TNOptHeader, L"CheckSum", GetHexString(opt_header32->CheckSum));

    //TODO: explained
    AddNode(TNOptHeader, L"Subsystem", GetDecString(opt_header32->Subsystem));

    AddNode(TNOptHeader, L"DllCharacteristics", GetHexString(opt_header32->DllCharacteristics));
    AddNode(TNOptHeader, L"SizeOfStackReserve", GetHexString(opt_header32->SizeOfStackReserve));
    AddNode(TNOptHeader, L"SizeOfStackCommit", GetHexString(opt_header32->SizeOfStackCommit));
    AddNode(TNOptHeader, L"SizeOfHeapReserve", GetHexString(opt_header32->SizeOfHeapReserve));
    AddNode(TNOptHeader, L"SizeOfHeapCommit", GetHexString(opt_header32->SizeOfHeapCommit));
    AddNode(TNOptHeader, L"LoaderFlags", GetHexString(opt_header32->LoaderFlags));
    AddNode(TNOptHeader, L"NumberOfRvaAndSizes", GetDecString(opt_header32->NumberOfRvaAndSizes));
  }
  else if(opt_header64)
  {
    TNOptHeader->Values[ColHeadersDescr->ItemIndex] = String(L"IMAGE_OPTIONAL_HEADER64");
    AddNode(TNOptHeader, L"Magic", GetHexString(opt_header64->Magic), L"PE32+");
    AddNode(TNOptHeader, L"MajorImageVersion", GetHexString(opt_header64->MajorImageVersion));
    AddNode(TNOptHeader, L"MinorLinkerVersion", GetHexString(opt_header64->MinorLinkerVersion));
    AddNode(TNOptHeader, L"SizeOfCode", GetHexString(opt_header64->SizeOfCode));
    AddNode(TNOptHeader, L"SizeOfInitializedData", GetHexString(opt_header64->SizeOfInitializedData));
    AddNode(TNOptHeader, L"SizeOfUninitializedData", GetHexString(opt_header64->SizeOfUninitializedData));
    AddNode(TNOptHeader, L"AddressOfEntryPoint", GetHexString(opt_header64->AddressOfEntryPoint));
    AddNode(TNOptHeader, L"BaseOfCode", GetHexString(opt_header64->BaseOfCode));
    AddNode(TNOptHeader, L"ImageBase", GetHexString(opt_header64->ImageBase));
    AddNode(TNOptHeader, L"SectionAlignment", GetHexString(opt_header64->SectionAlignment));
    AddNode(TNOptHeader, L"FileAlignment", GetHexString(opt_header64->FileAlignment));
    AddNode(TNOptHeader, L"MajorOperatingSystemVersion", GetHexString(opt_header64->MajorOperatingSystemVersion));
    AddNode(TNOptHeader, L"MinorOperatingSystemVersion", GetHexString(opt_header64->MinorOperatingSystemVersion));
    AddNode(TNOptHeader, L"MajorImageVersion", GetHexString(opt_header64->MajorImageVersion));
    AddNode(TNOptHeader, L"MinorImageVersion", GetHexString(opt_header64->MinorImageVersion));
    AddNode(TNOptHeader, L"MajorSubsystemVersion", GetHexString(opt_header64->MajorSubsystemVersion));
    AddNode(TNOptHeader, L"MinorSubsystemVersion", GetHexString(opt_header64->MinorSubsystemVersion));
    AddNode(TNOptHeader, L"Win32VersionValue", GetHexString(opt_header64->Win32VersionValue));
    AddNode(TNOptHeader, L"SizeOfImage", GetHexString(opt_header64->SizeOfImage));
    AddNode(TNOptHeader, L"SizeOfHeaders", GetHexString(opt_header64->SizeOfHeaders));
    AddNode(TNOptHeader, L"CheckSum", GetHexString(opt_header64->CheckSum));
    AddNode(TNOptHeader, L"Subsystem", GetHexString(opt_header64->Subsystem));
    AddNode(TNOptHeader, L"DllCharacteristics", GetHexString(opt_header64->DllCharacteristics));
    AddNode(TNOptHeader, L"SizeOfStackReserve", GetHexString(opt_header64->SizeOfStackReserve));
    AddNode(TNOptHeader, L"SizeOfStackCommit", GetHexString(opt_header64->SizeOfStackCommit));
    AddNode(TNOptHeader, L"SizeOfHeapReserve", GetHexString(opt_header64->SizeOfHeapReserve));
    AddNode(TNOptHeader, L"SizeOfHeapCommit", GetHexString(opt_header64->SizeOfHeapCommit));
    AddNode(TNOptHeader, L"LoaderFlags", GetHexString(opt_header64->LoaderFlags));
    AddNode(TNOptHeader, L"NumberOfRvaAndSizes", GetHexString(opt_header64->NumberOfRvaAndSizes));
  }
  ReadNodeState(L"TNOptHeader", TNOptHeader);

  const IMAGE_DATA_DIRECTORY* data_dir = NULL;
  if(opt_header32) data_dir = opt_header32->DataDirectory;
  else if(opt_header64) data_dir = opt_header64->DataDirectory;

  if(data_dir)
  {
    //IMAGE_DATA_DIRECTORY tables
    //00 - Export Table .edata Section (Image Only).
    //01 - Import Table The import table .idata Section.
    //02 - Resource Table .rsrc Section.
    //03 - Exception Table .pdata Section.
    //04 - Attribute Certificate Table (Image Only).
    //05 - Base Relocation Table .reloc Section (Image Only).
    //06 - Debug .debug Section.
    //07 - Architecture Reserved, must be 0
    //08 - Global Ptr The RVA of the value to be stored in the global pointer register. The size member of this structure must be set to zero.
    //09 - TLS Table .tls Section.
    //10 - Load Config Table (Image Only).
    //11 - Bound Import
    //12 - IAT Import Address Table.
    //13 - Delay-Load Import Tables (Image Only).
    //14 - CLR Runtime Header .cormeta Section (Object Only).
    //15 - Reserved, must be zero

    //IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
    //IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
    //IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
    //IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
    //IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
    //IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
    //IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
    //IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
    //IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
    //IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
    //IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
    //IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
    //IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
    //IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
    //IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
    //IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

    FillDataDirValue(0, L"00 .edata", L"Export table");
    FillDataDirValue(1, L"01 .idata", L"Import table");
    FillDataDirValue(2, L"02 .rsrc", L"Resource table");
    FillDataDirValue(3, L"03 .pdata", L"Exception table");
    FillDataDirValue(4, L"04 Certificate", L"Certificate table");
    FillDataDirValue(5, L"05 .reloc", L"Base relocation table");
    FillDataDirValue(6, L"06 .debug", L"Debugging information");
    FillDataDirValue(7, L"07 Architecture", L"Architecture-specific data");
    FillDataDirValue(8, L"08 GlobalPtr", L"Global pointer register");
    FillDataDirValue(9, L"09 .tls", L"Thread local storage table");
    FillDataDirValue(10, L"10 Load Config ", L"Load configuration table");
    FillDataDirValue(11, L"11 Bound Import", L"Bound import table");
    FillDataDirValue(12, L"12 IAT", L"Import address table");
    FillDataDirValue(13, L"13 Delay-Load", L"Delay import descriptor");
    FillDataDirValue(14, L"14 .cormeta", L"CLR header");
    FillDataDirValue(15, L"15 Reserved", L"Reserved");

    ReadNodeState(L"TNDataDir", TNDataDir);
  }

  //NOTE: IMAGE_SECTION_HEADER structure:
  //BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
  //union {
  //        DWORD   PhysicalAddress;
  //        DWORD   VirtualSize;
  //} Misc;
  //DWORD   VirtualAddress;
  //DWORD   SizeOfRawData;
  //DWORD   PointerToRawData;
  //DWORD   PointerToRelocations;
  //DWORD   PointerToLinenumbers;
  //WORD    NumberOfRelocations;
  //WORD    NumberOfLinenumbers;
  //DWORD   Characteristics;

  char section_name[IMAGE_SIZEOF_SHORT_NAME + 1];
  section_name[IMAGE_SIZEOF_SHORT_NAME] = 0;
  for(int section_index = 0; ; ++section_index)
  {
    const IMAGE_SECTION_HEADER* section_header = PEData.GetSectionHeader(section_index);
    if(NULL == section_header) break;
    ::memcpy_s(section_name, IMAGE_SIZEOF_SHORT_NAME, section_header->Name, IMAGE_SIZEOF_SHORT_NAME);

    TcxTreeListNode* section_node = TNSections->AddChild();
    section_node->Values[ColHeadersField->ItemIndex] = String().sprintf(L"%02u ", section_index) + String(section_name);

    AddNode(section_node, L"PhysicalAddress|VirtualSize", GetHexString(section_header->Misc.PhysicalAddress));
    AddNode(section_node, L"VirtualAddress", GetHexString(section_header->VirtualAddress));
    AddNode(section_node, L"SizeOfRawData", GetDecString(section_header->SizeOfRawData));
    AddNode(section_node, L"PointerToRawData", GetHexString(section_header->PointerToRawData));
    AddNode(section_node, L"PointerToRelocations", GetHexString(section_header->PointerToRelocations));
    AddNode(section_node, L"PointerToLinenumbers", GetHexString(section_header->PointerToLinenumbers));
    AddNode(section_node, L"NumberOfRelocations", GetDecString(section_header->NumberOfRelocations));
    AddNode(section_node, L"NumberOfLinenumbers", GetDecString(section_header->NumberOfLinenumbers));

    //TODO:
    AddNode(section_node, L"Characteristics", GetHexString(section_header->Characteristics));
  }
  ReadNodeState(L"TNSections", TNSections);
}
//---------------------------------------------------------------------------
void __fastcall TForm1::InitTSDependency()
{
  //TODO:
}
//---------------------------------------------------------------------------
void __fastcall TForm1::InitTSImports()
{
  //TODO:
}
//---------------------------------------------------------------------------
void __fastcall TForm1::InitTSExports()
{
  TcxUpdate tree_list_update(TLExports);

  TNExportDir = TLExports->Add();
  TNExportDir->Values[ColExportsField->ItemIndex] = String(L"Export Direcrory");
  TNExportDir->Values[ColExportsDescr->ItemIndex] = String(L"IMAGE_EXPORT_DIRECTORY");
  TNExports = TLExports->Add();
  TNExports->Values[ColExportsField->ItemIndex] = String(L"Export Table");

  const IMAGE_EXPORT_DIRECTORY* ed = PEData.GetExportDirectory();
  if(NULL == ed) return;

  LPCSTR file_name = reinterpret_cast<LPCSTR>(PEData.GetFilePointer(ed->Name));
  AddNode(TNExportDir, L"Characteristics", GetHexString(ed->Characteristics));
  AddNode(TNExportDir, L"TimeDateStamp", GetDateTimeString(ed->TimeDateStamp));
  AddNode(TNExportDir, L"MajorVersion", GetDecString(ed->MajorVersion));
  AddNode(TNExportDir, L"MinorVersion", GetDecString(ed->MinorVersion));
  AddNode(TNExportDir, L"Name", GetHexString(ed->Name), String(file_name));
  AddNode(TNExportDir, L"Base", GetHexString(ed->Base));
  AddNode(TNExportDir, L"NumberOfFunctions", GetDecString(ed->NumberOfFunctions));
  AddNode(TNExportDir, L"NumberOfNames", GetDecString(ed->NumberOfNames));
  AddNode(TNExportDir, L"AddressOfFunctions", GetHexString(ed->AddressOfFunctions));
  AddNode(TNExportDir, L"AddressOfNames", GetHexString(ed->AddressOfNames));
  AddNode(TNExportDir, L"AddressOfNameOrdinals", GetHexString(ed->AddressOfNameOrdinals));
  Options.ReadBool(L"TNExportDir") ? TNExportDir->Expand(false) : TNExportDir->Collapse(false);

  const DWORD* adresses = PEData.ExportFunctions;
  const DWORD* name_addr = PEData.ExportNames;
  const WORD* ordinals = PEData.ExportNameOrdinals;
  for(UINT index = 0; index < ed->NumberOfNames; ++index, ++adresses, ++name_addr, ++ordinals)
  {
      const DWORD addr = *adresses;
      LPCSTR name = reinterpret_cast<LPCSTR>(PEData.GetFilePointer(*name_addr));
      const DWORD ordinal = ed->Base + *ordinals;

      //TODO:
      //UnDecorateSymbolName();

      AddNode(TNExports, GetDecString(ordinal), GetHexString(addr), String(name));
  }
  Options.ReadBool(L"TNExports") ? TNExports->Expand(false) : TNExports->Collapse(false);
}
//---------------------------------------------------------------------------
void __fastcall TForm1::InitTSManifest()
{
  //TODO:
}
//---------------------------------------------------------------------------
void __fastcall TForm1::InitTSDump()
{
  //init all required tabs first
  if(TAB_EMPTY == TSGeneral->Tag) InitTSGeneral();
  if(TAB_EMPTY == TSHeaders->Tag) InitTSHeaders();
  if(TAB_EMPTY == TSDependency->Tag) InitTSDependency();
  if(TAB_EMPTY == TSImports->Tag) InitTSImports();
  if(TAB_EMPTY == TSExports->Tag) InitTSExports();
  if(TAB_EMPTY == TSManifest->Tag) InitTSManifest();

  String text;
  String tab_delimiter(L"-----------------------------------------------------------------------------\r\n");

  //TSGeneral
  text += L"GENERAL INFO\r\n" + tab_delimiter;
  GetFullNodeText(TNFileSystem, text);
  GetFullNodeText(TNVersionInfo, text);
  text += tab_delimiter;

  //TSHeaders
  text += L"HEADERS\r\n" + tab_delimiter;
  GetFullNodeText(TNDosHeader, text);
  GetFullNodeText(TNPEHeader, text);
  GetFullNodeText(TNOptHeader, text);
  GetFullNodeText(TNDataDir, text);
  GetFullNodeText(TNSections, text);
  text += tab_delimiter;

  //TODO: TSDependency

  //TODO: TSImports

  //TSExport
  text += L"EXPORTS\r\n" + tab_delimiter;
  GetFullNodeText(TNExportDir, text);
  GetFullNodeText(TNExports, text);
  text += tab_delimiter;

  //TODO: TSManifest

  MemoDump->Lines->Text = text;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::InitTSOptions()
{
  //TODO:
}
//---------------------------------------------------------------------------
void __fastcall TForm1::OnTabSheetShow(TObject *Sender)
{
  TTabSheet* tab_sheet = dynamic_cast<TTabSheet*>(Sender);
  if(NULL == tab_sheet)
  {
    assert(0);
    return;
  }
  if(tab_sheet->Tag != TAB_EMPTY) return;
  try
  {
    //TODO: set focus on the main control of this tab
    tab_sheet->Tag = TAB_OK;
    if(tab_sheet == TSGeneral) InitTSGeneral();
    else if(tab_sheet == TSHeaders) InitTSHeaders();
    else if(tab_sheet == TSDependency) InitTSDependency();
    else if(tab_sheet == TSImports) InitTSImports();
    else if(tab_sheet == TSExports) InitTSExports();
    else if(tab_sheet == TSManifest) InitTSManifest();
    else if(tab_sheet == TSDump) InitTSDump();
    else if(tab_sheet == TSOptions) InitTSOptions();
    else assert(0);
  }
  catch(Exception& E)
  {
    MessageBox(Handle, E.Message.c_str(), APP_NAME L" Error", MB_ICONERROR|MB_OK);
  }
  catch(...)
  {
    MessageBox(Handle, L"Undefined error", APP_NAME L" Error", MB_ICONERROR|MB_OK);
  }
}
//---------------------------------------------------------------------------
TcxTreeListNode* __fastcall TForm1::GetFocusedNode()
{
  TcxTreeList* tree_list = NULL;
  if(PCMain->ActivePage == TSGeneral) tree_list = TLGeneral;
  else if(PCMain->ActivePage == TSHeaders) tree_list = TLHeaders;
  else if(PCMain->ActivePage == TSExports) tree_list = TLExports;
  if(NULL == tree_list) return NULL;
  return tree_list->FocusedNode;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::GetFullNodeText(TcxTreeListNode* node, String& result, int level /*= 0*/)
{
  if(NULL == node) return;

  //skip empty top level nodes
  const int count = node->Count;
  if(0 == level && 0 == count) return;

  String field(VarToStr(node->Values[COL_FIELD_INDEX]));
  String value(VarToStr(node->Values[COL_VALUE_INDEX]));
  String descr(VarToStr(node->Values[COL_DESCR_INDEX]));

  const wchar_t* delimiter = L"    ";
  const wchar_t* indent = NULL;
  switch(level)
  {
  case 0: indent = L""; break;
  case 1: indent = L"    "; break;
  case 2: indent = L"        "; break;
  case 3: indent = L"            "; break;
  case 4: indent = L"                "; break;
  default:
    assert(false);
    indent = L"";
  }

  String node_text = String(indent) + field;
  if(!value.IsEmpty()) node_text += L" : " + value;
  if(!descr.IsEmpty()) node_text += L" : " + descr;
  result += node_text + L"\r\n";

  //child nodes
	for(int i = 0; i < count; ++i)
	{
		TcxTreeListNode* child_node = node->Items[i];
		GetFullNodeText(child_node, result, level + 1);
	}
}
//---------------------------------------------------------------------------
void __fastcall TForm1::PopupMenuPopup(TObject *Sender)
{
  MICopyValue->Enabled = false;
  MICopyDescr->Enabled = false;
  MICopyNode->Enabled = false;
  TcxTreeListNode* node = GetFocusedNode();
  if(NULL == node) return;
  String value = VarToStr(node->Values[COL_VALUE_INDEX]);
  String descr = VarToStr(node->Values[COL_DESCR_INDEX]);
  value.Trim();
  descr.Trim();
  MICopyValue->Enabled = !value.IsEmpty();
  MICopyDescr->Enabled = !descr.IsEmpty();
  MICopyNode->Enabled = true;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::MICopyValueClick(TObject *Sender)
{
  TcxTreeListNode* node = GetFocusedNode();
  if(NULL == node) return;
  String text = VarToStr(node->Values[COL_VALUE_INDEX]);
  CopyToClipboard(Handle, text.Trim().c_str());
}
//---------------------------------------------------------------------------
void __fastcall TForm1::MICopyDescrClick(TObject *Sender)
{
  TcxTreeListNode* node = GetFocusedNode();
  if(NULL == node) return;
  String text = VarToStr(node->Values[COL_DESCR_INDEX]);
  CopyToClipboard(Handle, text.Trim().c_str());
}
//---------------------------------------------------------------------------
void __fastcall TForm1::MICopyNodeClick(TObject *Sender)
{
  TcxTreeListNode* node = GetFocusedNode();
//  if(NULL == node) return;
//  String field = node->Values[COL_VALUE_INDEX];
//  String value = node->Values[COL_VALUE_INDEX];
//  String descr = node->Values[COL_DESCR_INDEX];
//  value.Trim();
//  descr.Trim();
//
//  const String delimiter = L" ";
//  String text = field + delimiter + value + delimiter + descr;

  //TODO: all child nodes too

  String text;
  GetFullNodeText(node, text);
  CopyToClipboard(Handle, text.Trim().c_str());
}
//---------------------------------------------------------------------------

