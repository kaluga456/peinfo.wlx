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
//values to string
//---------------------------------------------------------------------------
String GetDecString(int Value)
{
  return IntToStr(Value);
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
  for(int i = 0; i < Size; ++i)
  {
    result += String().sprintf(L"%04X ", Value[i]);
  }
  return result;
}
//---------------------------------------------------------------------------
String GetDateTimeString(time_t value)
{
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
//TForm1
//---------------------------------------------------------------------------
__fastcall TForm1::TForm1(TComponent* Owner, const TPEData& ped) : TForm(Owner), PEData(ped)
{
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FormCreate(TObject *Sender)
{
  //TODO:

  //TSHeaders
  TLHeaders->OptionsView->GridLineColor = clBtnFace;
  TNDosHeader = TLHeaders->Add();
  TNDosHeader->Values[ColHeadersField->ItemIndex] = L"DOS Header";
  TNDosHeader->Values[ColHeadersDescr->ItemIndex] = L"IMAGE_DOS_HEADER";
  TNPEHeader = TLHeaders->Add();
  TNOptHeader = TLHeaders->Add();
  TNOptHeader->Values[ColHeadersField->ItemIndex] = L"Optional Header";
  TNDataDir = TLHeaders->Add();
  TNSections = TLHeaders->Add();
  TNSections->Values[ColHeadersField->ItemIndex] = String(L"Sections");
  TNSections->Values[ColHeadersDescr->ItemIndex] = String(L"IMAGE_SECTION_HEADER");
  FillHeaders(); //TODO: OnShow() tab only

  //TSExports
  TLExports->OptionsView->GridLineColor = clBtnFace;
  TNExportDir = TLExports->Add();
  TNExportDir->Values[ColExportsField->ItemIndex] = L"Export Direcrory";
  TNExportDir->Values[ColExportsDescr->ItemIndex] = L"IMAGE_EXPORT_DIRECTORY";
  TNExports = TLExports->Add();
  TNExports->Values[ColExportsField->ItemIndex] = L"Export Table";
  //TNExports->Values[ColExportsDescr->ItemIndex] = L"";
  FillExports(); //TODO: OnShow() tab only

  //TSOptions
  LBAppInfo->Caption = APP_NAME L"  (Build: " APP_BUILD L")";
  CBDetectByContent->Enabled = false;

  const int last_tab = Options.ReadInt(L"LastTab");
  PCMain->ActivePageIndex = last_tab < PCMain->PageCount ? last_tab : 0;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FormDestroy(TObject *Sender)
{
  Options.WriteInt(L"LastTab", PCMain->ActivePageIndex);

  //TSHeaders
  Options.WriteBool(L"TNDosHeader", TNDosHeader->Expanded);
  Options.WriteBool(L"TNPEHeader", TNPEHeader->Expanded);
  Options.WriteBool(L"TNOptHeader", TNOptHeader->Expanded);
  Options.WriteBool(L"TNDataDir", TNDataDir->Expanded);
  Options.WriteBool(L"TNSections", TNSections->Expanded);

  //TSExports
  if(TNExportDir->HasChildren) Options.WriteBool(L"TNExportDir", TNExportDir->Expanded);
  if(TNExports->HasChildren) Options.WriteBool(L"TNExports", TNExports->Expanded);
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FillHeadersValue(TcxTreeListNode* Root, String Field, String Value, String Descr /*= L""*/)
{
  TcxTreeListNode* node = Root->AddChild();
  node->Values[ColHeadersField->ItemIndex] = Field;
  node->Values[ColHeadersValue->ItemIndex] = Value;
  node->Values[ColHeadersDescr->ItemIndex] = Descr;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FillDataDirValue(int Index, String Field, String Descr /*= L""*/)
{
  TcxTreeListNode* node = TNDataDir->AddChild();
  const IMAGE_DATA_DIRECTORY* idd = PEData.GetImageDirectoryEntry(Index);
  if(NULL == idd) return;
  node->Values[ColHeadersField->ItemIndex] = Field;
  node->Values[ColHeadersValue->ItemIndex] = GetHexString(idd->VirtualAddress) + L":" + GetHexString(idd->Size);
  node->Values[ColHeadersDescr->ItemIndex] = Descr;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FillHeaders()
{
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

    FillHeadersValue(TNDosHeader, L"Magic number", GetHexString(dos_header->e_magic));
    FillHeadersValue(TNDosHeader, L"Bytes on last page of file", GetDecString(dos_header->e_cblp));
    FillHeadersValue(TNDosHeader, L"Pages in file", GetDecString(dos_header->e_cp));
    FillHeadersValue(TNDosHeader, L"Relocations", GetHexString(dos_header->e_crlc));
    FillHeadersValue(TNDosHeader, L"Size of header in paragraphs", GetDecString(dos_header->e_cparhdr));
    FillHeadersValue(TNDosHeader, L"Minimum extra paragraphs needed", GetDecString(dos_header->e_minalloc));
    FillHeadersValue(TNDosHeader, L"Maximum extra paragraphs needed", GetDecString(dos_header->e_maxalloc));
    FillHeadersValue(TNDosHeader, L"Initial (relative) SS value", GetHexString(dos_header->e_ss));
    FillHeadersValue(TNDosHeader, L"Initial SP value", GetHexString(dos_header->e_sp));
    FillHeadersValue(TNDosHeader, L"Checksum", GetHexString(dos_header->e_csum));
    FillHeadersValue(TNDosHeader, L"Initial IP value", GetHexString(dos_header->e_ip));
    FillHeadersValue(TNDosHeader, L"Initial (relative) CS value", GetHexString(dos_header->e_cs));
    FillHeadersValue(TNDosHeader, L"File address of relocation table", GetHexString(dos_header->e_lfarlc));
    FillHeadersValue(TNDosHeader, L"Overlay number", GetHexString(dos_header->e_ovno));
    FillHeadersValue(TNDosHeader, L"Reserved words (e_res[4])", GetHexString(dos_header->e_res, 4));
    FillHeadersValue(TNDosHeader, L"OEM identifier", GetHexString(dos_header->e_oemid));
    FillHeadersValue(TNDosHeader, L"OEM information", GetHexString(dos_header->e_oeminfo));
    FillHeadersValue(TNDosHeader, L"Reserved words (e_res2[10])", GetHexString(dos_header->e_res2, 10));
    FillHeadersValue(TNDosHeader, L"File address of new exe header", GetHexString(dos_header->e_lfanew));

    Options.ReadBool(L"TNDosHeader") ? TNDosHeader->Expand(true) : TNDosHeader->Collapse(true);
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

    FillHeadersValue(TNPEHeader, L"Machine", GetHexString(file_header->Machine), GetMachineTypeString(file_header->Machine));
    FillHeadersValue(TNPEHeader, L"NumberOfSections", GetDecString(file_header->NumberOfSections));
    FillHeadersValue(TNPEHeader, L"TimeDateStamp", GetDecString(file_header->TimeDateStamp), ::GetDateTimeString(static_cast<const time_t>(file_header->TimeDateStamp)));
    FillHeadersValue(TNPEHeader, L"PointerToSymbolTable", GetHexString(file_header->PointerToSymbolTable));
    FillHeadersValue(TNPEHeader, L"NumberOfSymbols", GetDecString(file_header->NumberOfSymbols));
    FillHeadersValue(TNPEHeader, L"SizeOfOptionalHeader", GetDecString(file_header->SizeOfOptionalHeader));

    //TODO:
    //GetCoffCharsString(WORD value);
    FillHeadersValue(TNPEHeader, L"Characteristics", GetHexString(file_header->Characteristics));

    TNPEHeader->Values[ColHeadersField->ItemIndex] = L"COFF Header";
    TNPEHeader->Values[ColHeadersDescr->ItemIndex] = L"IMAGE_FILE_HEADER";
    Options.ReadBool(L"TNPEHeader") ? TNPEHeader->Expand(true) : TNPEHeader->Collapse(true);
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

    FillHeadersValue(TNOptHeader, L"Magic", GetHexString(opt_header32->Magic), L"PE32");
    FillHeadersValue(TNOptHeader, L"MajorImageVersion", GetDecString(opt_header32->MajorImageVersion));
    FillHeadersValue(TNOptHeader, L"MinorLinkerVersion", GetDecString(opt_header32->MinorLinkerVersion));
    FillHeadersValue(TNOptHeader, L"SizeOfCode", GetDecString(opt_header32->SizeOfCode));
    FillHeadersValue(TNOptHeader, L"SizeOfInitializedData", GetDecString(opt_header32->SizeOfInitializedData));
    FillHeadersValue(TNOptHeader, L"SizeOfUninitializedData", GetDecString(opt_header32->SizeOfUninitializedData));
    FillHeadersValue(TNOptHeader, L"AddressOfEntryPoint", GetHexString(opt_header32->AddressOfEntryPoint));
    FillHeadersValue(TNOptHeader, L"BaseOfCode", GetHexString(opt_header32->BaseOfCode));
    FillHeadersValue(TNOptHeader, L"BaseOfData", GetHexString(opt_header32->BaseOfData));
    FillHeadersValue(TNOptHeader, L"ImageBase", GetHexString(opt_header32->ImageBase));
    FillHeadersValue(TNOptHeader, L"SectionAlignment", GetHexString(opt_header32->SectionAlignment));
    FillHeadersValue(TNOptHeader, L"FileAlignment", GetHexString(opt_header32->FileAlignment));
    FillHeadersValue(TNOptHeader, L"MajorOperatingSystemVersion", GetDecString(opt_header32->MajorOperatingSystemVersion));
    FillHeadersValue(TNOptHeader, L"MinorOperatingSystemVersion", GetDecString(opt_header32->MinorOperatingSystemVersion));
    FillHeadersValue(TNOptHeader, L"MajorImageVersion", GetDecString(opt_header32->MajorImageVersion));
    FillHeadersValue(TNOptHeader, L"MinorImageVersion", GetDecString(opt_header32->MinorImageVersion));
    FillHeadersValue(TNOptHeader, L"MajorSubsystemVersion", GetDecString(opt_header32->MajorSubsystemVersion));
    FillHeadersValue(TNOptHeader, L"MinorSubsystemVersion", GetDecString(opt_header32->MinorSubsystemVersion));
    FillHeadersValue(TNOptHeader, L"Win32VersionValue", GetDecString(opt_header32->Win32VersionValue), L"Reserved, must be zero");
    FillHeadersValue(TNOptHeader, L"SizeOfImage", GetDecString(opt_header32->SizeOfImage));
    FillHeadersValue(TNOptHeader, L"SizeOfHeaders", GetDecString(opt_header32->SizeOfHeaders));
    FillHeadersValue(TNOptHeader, L"CheckSum", GetHexString(opt_header32->CheckSum));

    //TODO: explained
    FillHeadersValue(TNOptHeader, L"Subsystem", GetDecString(opt_header32->Subsystem));

    FillHeadersValue(TNOptHeader, L"DllCharacteristics", GetHexString(opt_header32->DllCharacteristics));
    FillHeadersValue(TNOptHeader, L"SizeOfStackReserve", GetHexString(opt_header32->SizeOfStackReserve));
    FillHeadersValue(TNOptHeader, L"SizeOfStackCommit", GetHexString(opt_header32->SizeOfStackCommit));
    FillHeadersValue(TNOptHeader, L"SizeOfHeapReserve", GetHexString(opt_header32->SizeOfHeapReserve));
    FillHeadersValue(TNOptHeader, L"SizeOfHeapCommit", GetHexString(opt_header32->SizeOfHeapCommit));
    FillHeadersValue(TNOptHeader, L"LoaderFlags", GetHexString(opt_header32->LoaderFlags));
    FillHeadersValue(TNOptHeader, L"NumberOfRvaAndSizes", GetDecString(opt_header32->NumberOfRvaAndSizes));

    TNOptHeader->Values[ColHeadersDescr->ItemIndex] = L"IMAGE_OPTIONAL_HEADER32";
    Options.ReadBool(L"TNOptHeader") ? TNOptHeader->Expand(true) : TNOptHeader->Collapse(true);
  }
  else if(opt_header64)
  {
    FillHeadersValue(TNOptHeader, L"Magic", GetHexString(opt_header64->Magic), L"PE32+");
    FillHeadersValue(TNOptHeader, L"MajorImageVersion", GetHexString(opt_header64->MajorImageVersion));
    FillHeadersValue(TNOptHeader, L"MinorLinkerVersion", GetHexString(opt_header64->MinorLinkerVersion ));
    FillHeadersValue(TNOptHeader, L"SizeOfCode", GetHexString(opt_header64->SizeOfCode));
    FillHeadersValue(TNOptHeader, L"SizeOfInitializedData", GetHexString(opt_header64->SizeOfInitializedData));
    FillHeadersValue(TNOptHeader, L"SizeOfUninitializedData", GetHexString(opt_header64->SizeOfUninitializedData));
    FillHeadersValue(TNOptHeader, L"AddressOfEntryPoint", GetHexString(opt_header64->AddressOfEntryPoint));
    FillHeadersValue(TNOptHeader, L"BaseOfCode", GetHexString(opt_header64->BaseOfCode));
    FillHeadersValue(TNOptHeader, L"ImageBase", GetHexString(opt_header64->ImageBase));
    FillHeadersValue(TNOptHeader, L"SectionAlignment", GetHexString(opt_header64->SectionAlignment));
    FillHeadersValue(TNOptHeader, L"FileAlignment", GetHexString(opt_header64->FileAlignment));
    FillHeadersValue(TNOptHeader, L"MajorOperatingSystemVersion", GetHexString(opt_header64->MajorOperatingSystemVersion));
    FillHeadersValue(TNOptHeader, L"MinorOperatingSystemVersion", GetHexString(opt_header64->MinorOperatingSystemVersion));
    FillHeadersValue(TNOptHeader, L"MajorImageVersion", GetHexString(opt_header64->MajorImageVersion));
    FillHeadersValue(TNOptHeader, L"MinorImageVersion", GetHexString(opt_header64->MinorImageVersion));
    FillHeadersValue(TNOptHeader, L"MajorSubsystemVersion", GetHexString(opt_header64->MajorSubsystemVersion));
    FillHeadersValue(TNOptHeader, L"MinorSubsystemVersion", GetHexString(opt_header64->MinorSubsystemVersion));
    FillHeadersValue(TNOptHeader, L"Win32VersionValue", GetHexString(opt_header64->Win32VersionValue));
    FillHeadersValue(TNOptHeader, L"SizeOfImage", GetHexString(opt_header64->SizeOfImage));
    FillHeadersValue(TNOptHeader, L"SizeOfHeaders", GetHexString(opt_header64->SizeOfHeaders));
    FillHeadersValue(TNOptHeader, L"CheckSum", GetHexString(opt_header64->CheckSum));
    FillHeadersValue(TNOptHeader, L"Subsystem", GetHexString(opt_header64->Subsystem));
    FillHeadersValue(TNOptHeader, L"DllCharacteristics", GetHexString(opt_header64->DllCharacteristics));
    FillHeadersValue(TNOptHeader, L"SizeOfStackReserve", GetHexString(opt_header64->SizeOfStackReserve));
    FillHeadersValue(TNOptHeader, L"SizeOfStackCommit", GetHexString(opt_header64->SizeOfStackCommit));
    FillHeadersValue(TNOptHeader, L"SizeOfHeapReserve", GetHexString(opt_header64->SizeOfHeapReserve));
    FillHeadersValue(TNOptHeader, L"SizeOfHeapCommit", GetHexString(opt_header64->SizeOfHeapCommit));
    FillHeadersValue(TNOptHeader, L"LoaderFlags", GetHexString(opt_header64->LoaderFlags));
    FillHeadersValue(TNOptHeader, L"NumberOfRvaAndSizes", GetHexString(opt_header64->NumberOfRvaAndSizes));

    TNOptHeader->Values[ColHeadersField->ItemIndex] = L"Optional Header";
    TNOptHeader->Values[ColHeadersDescr->ItemIndex] = L"IMAGE_OPTIONAL_HEADER64";
    Options.ReadBool(L"TNOptHeader") ? TNOptHeader->Expand(true) : TNOptHeader->Collapse(true);
  }

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

    TNDataDir->Values[ColHeadersField->ItemIndex] = L"Data Directory";
    TNDataDir->Values[ColHeadersDescr->ItemIndex] = L"IMAGE_DATA_DIRECTORY";
    Options.ReadBool(L"TNDataDir") ? TNDataDir->Expand(true) : TNDataDir->Collapse(true);
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
      section_node->Values[ColHeadersField->ItemIndex] = String().sprintf(L"%02u ", section_index) + String(section_name);;

      FillHeadersValue(section_node, L"PhysicalAddress|VirtualSize", GetHexString(section_header->Misc.PhysicalAddress));
      FillHeadersValue(section_node, L"VirtualAddress", GetHexString(section_header->VirtualAddress));
      FillHeadersValue(section_node, L"SizeOfRawData", GetDecString(section_header->SizeOfRawData));
      FillHeadersValue(section_node, L"PointerToRawData", GetHexString(section_header->PointerToRawData));
      FillHeadersValue(section_node, L"PointerToRelocations", GetHexString(section_header->PointerToRelocations));
      FillHeadersValue(section_node, L"PointerToLinenumbers", GetHexString(section_header->PointerToLinenumbers));
      FillHeadersValue(section_node, L"NumberOfRelocations", GetDecString(section_header->NumberOfRelocations));
      FillHeadersValue(section_node, L"NumberOfLinenumbers", GetDecString(section_header->NumberOfLinenumbers));

      //TODO:
      FillHeadersValue(section_node, L"Characteristics\n", GetHexString(section_header->Characteristics));
  }
  Options.ReadBool(L"TNSections") ? TNSections->Expand(false) : TNSections->Collapse(false);
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FillExportsValue(TcxTreeListNode* Root, String Field, String Value, String Descr /*= L""*/)
{
  TcxTreeListNode* node = Root->AddChild();
  node->Values[ColExportsField->ItemIndex] = Field;
  node->Values[ColExportsValue->ItemIndex] = Value;
  node->Values[ColExportsDescr->ItemIndex] = Descr;
}
//---------------------------------------------------------------------------
void __fastcall TForm1::FillExports()
{
  const IMAGE_EXPORT_DIRECTORY* ed = PEData.GetExportDirectory();
  if(NULL == ed) return;

  LPCSTR file_name = reinterpret_cast<LPCSTR>(PEData.GetFilePointer(ed->Name));
  FillExportsValue(TNExportDir, L"Characteristics", GetHexString(ed->Characteristics));
  FillExportsValue(TNExportDir, L"TimeDateStamp", GetDateTimeString(ed->TimeDateStamp));
  FillExportsValue(TNExportDir, L"MajorVersion", GetDecString(ed->MajorVersion));
  FillExportsValue(TNExportDir, L"MinorVersion", GetDecString(ed->MinorVersion));
  FillExportsValue(TNExportDir, L"Name", GetHexString(ed->Name), String(file_name));
  FillExportsValue(TNExportDir, L"Base", GetHexString(ed->Base));
  FillExportsValue(TNExportDir, L"NumberOfFunctions", GetDecString(ed->NumberOfFunctions));
  FillExportsValue(TNExportDir, L"NumberOfNames", GetDecString(ed->NumberOfNames));
  FillExportsValue(TNExportDir, L"AddressOfFunctions", GetHexString(ed->AddressOfFunctions));
  FillExportsValue(TNExportDir, L"AddressOfNames", GetHexString(ed->AddressOfNames));
  FillExportsValue(TNExportDir, L"AddressOfNameOrdinals", GetHexString(ed->AddressOfNameOrdinals));
  Options.ReadBool(L"TNExportDir") ? TNExportDir->Expand(false) : TNExportDir->Collapse(false);

  //_tprintf(_T("    %-8s|%-8s|%s\n"), _T("Address"), _T("Ordinal"), _T("Name"));
  const DWORD* adresses = PEData.ExportFunctions;
  const DWORD* name_addr = PEData.ExportNames;
  const WORD* ordinals = PEData.ExportNameOrdinals;
  for(UINT index = 0; index < ed->NumberOfFunctions; ++index, ++adresses, ++name_addr, ++ordinals)
  {
      const DWORD addr = *adresses;
      LPCSTR name = reinterpret_cast<LPCSTR>(PEData.GetFilePointer(*name_addr));
      const DWORD ordinal = ed->Base + *ordinals;
      FillExportsValue(TNExports, GetDecString(ordinal), GetHexString(addr), String(name));
  }
  Options.ReadBool(L"TNExports") ? TNExports->Expand(false) : TNExports->Collapse(false);
}
//---------------------------------------------------------------------------
