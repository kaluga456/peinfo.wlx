//---------------------------------------------------------------------------
#ifndef MainFormH
#define MainFormH
//---------------------------------------------------------------------------
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.Forms.hpp>
#include <Vcl.Menus.hpp>
#include <Vcl.ComCtrls.hpp>
#include "cxControls.hpp"
#include "cxCustomData.hpp"
#include "cxGraphics.hpp"
#include "cxInplaceContainer.hpp"
#include "cxLookAndFeelPainters.hpp"
#include "cxLookAndFeels.hpp"
#include "cxStyles.hpp"
#include "cxTL.hpp"
#include "cxTLdxBarBuiltInMenu.hpp"
#include "cxTextEdit.hpp"
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
  TTabSheet *TSGeneral;
  TTabSheet *TSHeaders;
  TTabSheet *TSDependency;
  TTabSheet *TSImports;
  TTabSheet *TSExports;
  TPageControl *PCMain;
  TTabSheet *TSManifest;
  TTabSheet *TSDump;
  TTabSheet *TSOptions;
  TcxTreeList *TLGeneral;
  TcxTreeList *TLHeaders;
  TcxTreeListColumn *ColHeadersField;
  TcxTreeListColumn *ColHeadersValue;
  TcxTreeListColumn *ColHeadersDescr;
  TButton *Button1;
  TLabel *LBAppInfo;
  TCheckBox *CBDetectByContent;
  TcxTreeList *TLExports;
  TcxTreeListColumn *ColExportsField;
  TcxTreeListColumn *ColExportsValue;
  TcxTreeListColumn *ColExportsDescr;
  void __fastcall FormCreate(TObject *Sender);
  void __fastcall FormDestroy(TObject *Sender);
  void __fastcall TSGeneralShow(TObject *Sender);

public:		// User declarations
  __fastcall TForm1(TComponent* Owner, const TPEData& ped);

private:	// User declarations
  const TPEData& PEData;
  TPEOptions Options;
  bool __fastcall Is64() const {return PEData.GetNTHeaders64();}

  //TSGeneral
  TcxTreeListNode* TNFileSystem;
  TcxTreeListNode* TNVersionInfo;
  void __fastcall FillGeneral();

  //TSHeaders top nodes
  TcxTreeListNode* TNDosHeader;
  TcxTreeListNode* TNPEHeader;
  TcxTreeListNode* TNOptHeader;
  TcxTreeListNode* TNDataDir;
  TcxTreeListNode* TNSections;
  void __fastcall FillHeadersValue(TcxTreeListNode* Root, String Field, String Value, String Descr = L"");
  void __fastcall FillDataDirValue(int Index, String Field, String Descr = L"");
  void __fastcall FillHeaders();

  //TSExport
  TcxTreeListNode* TNExportDir;
  TcxTreeListNode* TNExports;
  void __fastcall FillExportsValue(TcxTreeListNode* Root, String Field, String Value, String Descr = L"");
  void __fastcall FillExports();
};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif

