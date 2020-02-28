//---------------------------------------------------------------------------
#include "peinfo_pch.h"
#pragma hdrstop
#include "Options.h"

const wchar_t* const APP_REG_PATH = L"\\Software\\" APP_NAME;
//---------------------------------------------------------------------------
__fastcall TPEOptions::TPEOptions(): Registry(NULL)
{
  try
  {
    Registry = new TRegistry;
    Registry->RootKey = HKEY_CURRENT_USER;
    if(false == Registry->OpenKey(APP_REG_PATH, false)) return;
  }
  catch(...) {}
}
//---------------------------------------------------------------------------
__fastcall TPEOptions::~TPEOptions()
{
  delete Registry;
}
//---------------------------------------------------------------------------
bool __fastcall TPEOptions::ReadBool(String Name, bool Default /*= false*/)
{
  if(NULL == Registry) return Default;
  return Registry->ValueExists(Name) ? Registry->ReadBool(Name) : Default;
}
//---------------------------------------------------------------------------
int __fastcall TPEOptions::ReadInt(String Name, int Default /*= 0*/)
{
  if(NULL == Registry) return Default;
  return Registry->ValueExists(Name) ? Registry->ReadInteger(Name) : Default;
}
//---------------------------------------------------------------------------
void __fastcall TPEOptions::WriteBool(String Name, bool Value)
{
  if(NULL == Registry) return;
  Registry->WriteBool(Name, Value);
}
//---------------------------------------------------------------------------
void __fastcall TPEOptions::WriteInt(String Name, int Value)
{
  if(NULL == Registry) return;
  Registry->WriteInteger(Name, Value);
}
//---------------------------------------------------------------------------
#pragma package(smart_init)

