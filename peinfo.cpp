//---------------------------------------------------------------------------
#include "peinfo_pch.h"
#pragma hdrstop
#include "PEData.h"
#include "Options.h"
#include "MainForm.h"
#include "peinfo.h"

#pragma package(smart_init)

static TForm1* MainWnd = NULL;
static TPEData PEData;
//---------------------------------------------------------------------------
//TODO:
LPCTSTR PARSE_STRING = _T("ext=\"EXE\" | ext=\"DLL\" | ext=\"BPL\"");
//---------------------------------------------------------------------------
static void ShowError(HWND parent_wnd, LPCTSTR error_string)
{
  ::MessageBox(parent_wnd, error_string, _T("Error"), MB_ICONERROR|MB_OK);
}
//---------------------------------------------------------------------------
////WLX exports
//---------------------------------------------------------------------------
HWND __stdcall ListLoad(HWND ParentWin, char* FileToLoad, int ShowFlags)
{
  try
  {
    //read file
    //TODO: collect all additional info here
    String file_name(FileToLoad);
    const bool result = PEData.ParseFile(file_name.c_str());
    if(false == result)
    {
      ShowError(ParentWin, PEData.GetErrorString());
      PEData.Reset();
      return NULL;
    }

    //create GUI
    MainWnd = new TForm1(NULL, PEData);
    MainWnd->ParentWindow = ParentWin;
    MainWnd->Show();

    //ok
    return MainWnd->Handle;
  }
  catch(Exception& E)
  {
    ShowError(ParentWin, E.Message.c_str());
  }
  catch(...)
  {
    ShowError(ParentWin, _T("Unknown error"));
  }
  return NULL;
}
//---------------------------------------------------------------------------
void __stdcall ListCloseWindow(HWND ListWin)
{
  delete MainWnd;
  PEData.Reset();
}
//---------------------------------------------------------------------------
void __stdcall ListGetDetectString(char* DetectString, int maxlen)
{
  //TODO: edit as options
  strcpy(DetectString, "ext=\"EXE\" | ext=\"DLL\" | ext=\"BPL\"");
}
//---------------------------------------------------------------------------
int __stdcall ListSearchText(HWND ListWin, char* SearchString, int SearchParameter)
{
  return 0;
}
//---------------------------------------------------------------------------
int __stdcall ListSendCommand(HWND ListWin, int Command, int Parameter)
{
  //TODO:
  return 0;
}
//---------------------------------------------------------------------------
int __stdcall ListPrint(HWND ListWin, char* FileToPrint, char* DefPrinter, int PrintFlags, RECT* Margins)
{
  //TODO:
  return 0;
}
//---------------------------------------------------------------------------
int __stdcall ListNotificationReceived(HWND ListWin, int Message, WPARAM wParam, LPARAM lParam)
{
  //TODO:
  return 0;
}
//---------------------------------------------------------------------------
void __stdcall ListSetDefaultParams(ListDefaultParamStruct* dps)
{
  //TODO:
}
//---------------------------------------------------------------------------
HBITMAP __stdcall ListGetPreviewBitmap(char* FileToLoad, int width, int height, char* contentbuf, int contentbuflen)
{
  //TODO:
  return NULL;
}
//---------------------------------------------------------------------------
