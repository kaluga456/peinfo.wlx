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
#include <Vcl.ExtCtrls.hpp>
//---------------------------------------------------------------------------
//TODO: pass unhandled messages to parent window
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
  TTabSheet *TSHeaders;
  TTabSheet *TSDependency;
  TTabSheet *TSImports;
  TTabSheet *TSExports;
  TTabSheet *TSManifest;
  TTabSheet *TSDump;
  TTabSheet *TSOptions;
  TcxTreeList *TLHeaders;
  TcxTreeListColumn *ColHeadersField;
  TcxTreeListColumn *ColHeadersValue;
  TcxTreeListColumn *ColHeadersDescr;
  TPageControl *PCMain;
  TLabel *LBAppInfo;
  TCheckBox *CBDetectByContent;
  TcxTreeList *TLExports;
  TcxTreeListColumn *ColExportsField;
  TcxTreeListColumn *ColExportsValue;
  TcxTreeListColumn *ColExportsDescr;
  TTabSheet *TSGeneral;
  TcxTreeList *TLGeneral;
  TcxTreeListColumn *ColGeneralField;
  TcxTreeListColumn *ColGeneralValue;
  TcxTreeListColumn *ColGeneralDescr;
  TPopupMenu *PopupMenu;
  TMenuItem *MICopyValue;
  TMenuItem *MICopyDescr;
  TMenuItem *MICopyNode;
  TMemo *MemoDump;
  void __fastcall FormCreate(TObject *Sender);
  void __fastcall FormDestroy(TObject *Sender);
  void __fastcall OnTabSheetShow(TObject *Sender);
  void __fastcall PopupMenuPopup(TObject *Sender);
  void __fastcall MICopyValueClick(TObject *Sender);
  void __fastcall MICopyDescrClick(TObject *Sender);
  void __fastcall MICopyNodeClick(TObject *Sender);

public:		// User declarations
  __fastcall TForm1(TComponent* Owner, String full_file_name, const TPEData& ped);

private:	// User declarations
  String FullFileName;
  const TPEData& PEData;
  TPEOptions Options;
  bool __fastcall Is64() const {return PEData.GetNTHeaders64();}

  //node expand state
  void __fastcall ReadNodeState(String reg_key, TcxTreeListNode* node);
  void __fastcall WriteNodeState(String reg_key, TcxTreeListNode* node);

  void __fastcall AddNode(TcxTreeListNode* root_node, String field, String value, String descr = L"");
  TcxTreeListNode* __fastcall GetFocusedNode();
  void __fastcall GetFullNodeText(TcxTreeListNode* node, String& result, int level = 0);

  //TSGeneral
  TcxTreeListNode* TNFileSystem;
  TcxTreeListNode* TNVersionInfo;
  void __fastcall InitTSGeneral();

  //TSHeaders
  TcxTreeListNode* TNDosHeader;
  TcxTreeListNode* TNPEHeader;
  TcxTreeListNode* TNOptHeader;
  TcxTreeListNode* TNDataDir;
  TcxTreeListNode* TNSections;
  void __fastcall FillDataDirValue(int Index, String Field, String Descr = L"");
  void __fastcall InitTSHeaders();

  //TSDependency
  void __fastcall InitTSDependency();

  //TSImports
  void __fastcall InitTSImports();

  //TSExport
  TcxTreeListNode* TNExportDir;
  TcxTreeListNode* TNExports;
  void __fastcall InitTSExports();

  //TSManifest
  void __fastcall InitTSManifest();

  //TSDump
  void __fastcall InitTSDump();

  //TSOptions
  void __fastcall InitTSOptions();
};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif

