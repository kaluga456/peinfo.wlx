#ifndef peinfoH
#define peinfoH
//---------------------------------------------------------------------------
//WLX exports
//---------------------------------------------------------------------------
//TODO:
struct ListDefaultParamStruct
{
	int size;
	DWORD PluginInterfaceVersionLow;
	DWORD PluginInterfaceVersionHi;
	char DefaultIniName[MAX_PATH];
};
//---------------------------------------------------------------------------
//TODO:
extern "C"
{
HWND __declspec(dllexport) __stdcall ListLoad(HWND ParentWin,char* FileToLoad,int ShowFlags);
void __declspec(dllexport) __stdcall ListCloseWindow(HWND ListWin);
void __declspec(dllexport)__stdcall ListGetDetectString(char* DetectString,int maxlen);
int __declspec(dllexport) __stdcall ListSearchText(HWND ListWin,char* SearchString,int SearchParameter);
int __declspec(dllexport) __stdcall ListSendCommand(HWND ListWin,int Command,int Parameter);
int __declspec(dllexport) __stdcall ListPrint(HWND ListWin,char* FileToPrint,char* DefPrinter, int PrintFlags,RECT* Margins);
int __declspec(dllexport) __stdcall ListNotificationReceived(HWND ListWin,int Message,WPARAM wParam,LPARAM lParam);
void __declspec(dllexport) __stdcall ListSetDefaultParams(ListDefaultParamStruct* dps);
HBITMAP __declspec(dllexport) __stdcall ListGetPreviewBitmap(char* FileToLoad,int width,int height, char* contentbuf,int contentbuflen);
}
//---------------------------------------------------------------------------
#endif

