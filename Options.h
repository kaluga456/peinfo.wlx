#ifndef OptionsH
#define OptionsH
//---------------------------------------------------------------------------
#define APP_NAME L"peinfo.dll"
#define APP_BUILD _T(__DATE__)
#define APP_URL _T("https://github.com/kaluga456/peinfo.wlx");
//---------------------------------------------------------------------------
class TPEOptions
{
public:
  __fastcall TPEOptions();
  __fastcall ~TPEOptions();

  bool __fastcall ReadBool(String Name, bool Default = false);
  int __fastcall ReadInt(String Name, int Default = 0);
  void __fastcall WriteBool(String Name, bool Value);
  void __fastcall WriteInt(String Name, int Value);

private:
  TRegistry* Registry;
};
//---------------------------------------------------------------------------
#endif

