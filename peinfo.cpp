//---------------------------------------------------------------------------
#include "peinfo_pch.h"
#pragma hdrstop
#include "PEData.h"
#include "Options.h"
#include "MainForm.h"
#include "peinfo.h"

#pragma package(smart_init)

static HWND ParentWindow = NULL;
static TPEData PEData;
static TForm1* MainWnd = NULL;
//---------------------------------------------------------------------------
static void ShowError(HWND parent_wnd, LPCTSTR error_string)
{
  MessageBox(parent_wnd, error_string, APP_NAME L" Error", MB_ICONERROR|MB_OK);
}
//---------------------------------------------------------------------------
//WLX exports
//---------------------------------------------------------------------------
HWND __stdcall ListLoad(HWND ParentWin, char* FileToLoad, int ShowFlags)
{
  try
  {
    ParentWindow = ParentWin;

    //read file
    //TODO: collect all additional info here
    String file_name(FileToLoad);
    const bool result = PEData.ParseFile(file_name.c_str());
    if(false == result)
    {
      ShowError(ParentWin, PEData.GetErrorString());
      PEData.Reset();

      //TODO: may be some info can be retrieved by MainForm?
      return NULL;
    }

    //create GUI
    MainWnd = new TForm1(NULL, file_name, PEData);
    MainWnd->ParentWindow = ParentWin;
    MainWnd->Show();

    //ok
    return MainWnd->Handle;
  }
  catch(Exception& E)
  {
    ShowError(ParentWindow, E.Message.c_str());
  }
  catch(...)
  {
    ShowError(ParentWindow, _T("Unknown error"));
  }
  return NULL;
}
//---------------------------------------------------------------------------
void __stdcall ListCloseWindow(HWND ListWin)
{
  try
  {
    delete MainWnd;
    PEData.Reset();
  }
  catch(Exception& E)
  {
    #ifdef _DEBUG
    ShowError(NULL, E.Message.c_str());
    #endif
  }
  catch(...)
  {
    #ifdef _DEBUG
    ShowError(NULL, _T("Unknown error"));
    #endif
  }
}
//---------------------------------------------------------------------------
void __stdcall ListGetDetectString(char* DetectString, int maxlen)
{
  try
  {
    //TODO: make detect string from options
    const char* detect_string = "ext=\"EXE\" | ext=\"DLL\" | ext=\"BPL\"";

    const int detect_string_size = ::strlen(detect_string);
    if(detect_string_size > maxlen) return;
    ::strcpy(DetectString, detect_string);
  }
  catch(Exception& E)
  {
    #ifdef _DEBUG
    ShowError(ParentWindow, E.Message.c_str());
    #endif
  }
  catch(...)
  {
    #ifdef _DEBUG
    ShowError(ParentWindow, _T("Unknown error"));
    #endif
  }
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
