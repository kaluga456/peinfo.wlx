object Form1: TForm1
  Left = 0
  Top = 0
  BorderStyle = bsNone
  Caption = 'Form1'
  ClientHeight = 538
  ClientWidth = 917
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -13
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 120
  TextHeight = 16
  object PCMain: TPageControl
    Left = 0
    Top = 0
    Width = 917
    Height = 538
    ActivePage = TSDump
    Align = alClient
    Style = tsFlatButtons
    TabOrder = 0
    object TSGeneral: TTabSheet
      Caption = 'General'
      ImageIndex = 7
      OnShow = OnTabSheetShow
      ExplicitLeft = 0
      ExplicitTop = 0
      ExplicitWidth = 0
      ExplicitHeight = 0
      object TLGeneral: TcxTreeList
        Left = 0
        Top = 0
        Width = 909
        Height = 504
        Hint = ''
        Align = alClient
        Bands = <
          item
          end>
        Navigator.Buttons.CustomButtons = <>
        OptionsBehavior.MultiSort = False
        OptionsBehavior.Sorting = False
        OptionsCustomizing.BandCustomizing = False
        OptionsCustomizing.ColumnCustomizing = False
        OptionsCustomizing.ColumnMoving = False
        OptionsCustomizing.ColumnVertSizing = False
        OptionsData.Editing = False
        OptionsData.Deleting = False
        OptionsSelection.CellSelect = False
        OptionsSelection.HideSelection = True
        OptionsView.ColumnAutoWidth = True
        OptionsView.GridLines = tlglBoth
        OptionsView.TreeLineStyle = tllsSolid
        PopupMenu = PopupMenu
        TabOrder = 0
        object ColGeneralField: TcxTreeListColumn
          Caption.Text = 'Field'
          DataBinding.ValueType = 'String'
          Position.ColIndex = 0
          Position.RowIndex = 0
          Position.BandIndex = 0
          Summary.FooterSummaryItems = <>
          Summary.GroupFooterSummaryItems = <>
        end
        object ColGeneralValue: TcxTreeListColumn
          Caption.Text = 'Value'
          DataBinding.ValueType = 'String'
          Position.ColIndex = 1
          Position.RowIndex = 0
          Position.BandIndex = 0
          Summary.FooterSummaryItems = <>
          Summary.GroupFooterSummaryItems = <>
        end
        object ColGeneralDescr: TcxTreeListColumn
          Caption.Text = 'Description'
          DataBinding.ValueType = 'String'
          Position.ColIndex = 2
          Position.RowIndex = 0
          Position.BandIndex = 0
          Summary.FooterSummaryItems = <>
          Summary.GroupFooterSummaryItems = <>
        end
      end
    end
    object TSHeaders: TTabSheet
      Caption = 'Headers'
      ImageIndex = 1
      OnShow = OnTabSheetShow
      ExplicitLeft = 0
      ExplicitTop = 0
      ExplicitWidth = 0
      ExplicitHeight = 0
      object TLHeaders: TcxTreeList
        Left = 0
        Top = 0
        Width = 909
        Height = 504
        Hint = ''
        Align = alClient
        Bands = <
          item
          end>
        Navigator.Buttons.CustomButtons = <>
        OptionsBehavior.MultiSort = False
        OptionsBehavior.Sorting = False
        OptionsCustomizing.ColumnMoving = False
        OptionsData.Editing = False
        OptionsData.Deleting = False
        OptionsSelection.CellSelect = False
        OptionsSelection.HideSelection = True
        OptionsView.ColumnAutoWidth = True
        OptionsView.GridLines = tlglBoth
        OptionsView.TreeLineStyle = tllsSolid
        PopupMenu = PopupMenu
        TabOrder = 0
        object ColHeadersField: TcxTreeListColumn
          Caption.Text = 'Field'
          DataBinding.ValueType = 'String'
          Position.ColIndex = 0
          Position.RowIndex = 0
          Position.BandIndex = 0
          Summary.FooterSummaryItems = <>
          Summary.GroupFooterSummaryItems = <>
        end
        object ColHeadersValue: TcxTreeListColumn
          Caption.Text = 'Value'
          DataBinding.ValueType = 'String'
          Position.ColIndex = 1
          Position.RowIndex = 0
          Position.BandIndex = 0
          Summary.FooterSummaryItems = <>
          Summary.GroupFooterSummaryItems = <>
        end
        object ColHeadersDescr: TcxTreeListColumn
          Caption.Text = 'Description'
          DataBinding.ValueType = 'String'
          Position.ColIndex = 2
          Position.RowIndex = 0
          Position.BandIndex = 0
          Summary.FooterSummaryItems = <>
          Summary.GroupFooterSummaryItems = <>
        end
      end
    end
    object TSDependency: TTabSheet
      Caption = 'Dependency'
      ImageIndex = 2
      OnShow = OnTabSheetShow
      ExplicitLeft = 0
      ExplicitTop = 0
      ExplicitWidth = 0
      ExplicitHeight = 0
    end
    object TSImports: TTabSheet
      Caption = 'Imports'
      ImageIndex = 3
      OnShow = OnTabSheetShow
      ExplicitLeft = 0
      ExplicitTop = 0
      ExplicitWidth = 0
      ExplicitHeight = 0
    end
    object TSExports: TTabSheet
      Caption = 'Exports'
      ImageIndex = 4
      OnShow = OnTabSheetShow
      ExplicitLeft = 0
      ExplicitTop = 0
      ExplicitWidth = 0
      ExplicitHeight = 0
      object TLExports: TcxTreeList
        Left = 0
        Top = 0
        Width = 909
        Height = 504
        Hint = ''
        Align = alClient
        Bands = <
          item
          end>
        Navigator.Buttons.CustomButtons = <>
        OptionsBehavior.MultiSort = False
        OptionsBehavior.Sorting = False
        OptionsCustomizing.ColumnMoving = False
        OptionsData.Editing = False
        OptionsData.Deleting = False
        OptionsSelection.CellSelect = False
        OptionsSelection.HideSelection = True
        OptionsView.ColumnAutoWidth = True
        OptionsView.GridLines = tlglBoth
        OptionsView.TreeLineStyle = tllsSolid
        PopupMenu = PopupMenu
        TabOrder = 0
        object ColExportsField: TcxTreeListColumn
          Caption.Text = 'Field'
          DataBinding.ValueType = 'String'
          Position.ColIndex = 0
          Position.RowIndex = 0
          Position.BandIndex = 0
          Summary.FooterSummaryItems = <>
          Summary.GroupFooterSummaryItems = <>
        end
        object ColExportsValue: TcxTreeListColumn
          Caption.Text = 'Value'
          DataBinding.ValueType = 'String'
          Position.ColIndex = 1
          Position.RowIndex = 0
          Position.BandIndex = 0
          Summary.FooterSummaryItems = <>
          Summary.GroupFooterSummaryItems = <>
        end
        object ColExportsDescr: TcxTreeListColumn
          Caption.Text = 'Description'
          DataBinding.ValueType = 'String'
          Position.ColIndex = 2
          Position.RowIndex = 0
          Position.BandIndex = 0
          Summary.FooterSummaryItems = <>
          Summary.GroupFooterSummaryItems = <>
        end
      end
    end
    object TSManifest: TTabSheet
      Caption = 'Manifest'
      ImageIndex = 5
      OnShow = OnTabSheetShow
      ExplicitLeft = 0
      ExplicitTop = 0
      ExplicitWidth = 0
      ExplicitHeight = 0
    end
    object TSDump: TTabSheet
      Caption = 'Dump'
      ImageIndex = 6
      OnShow = OnTabSheetShow
      ExplicitLeft = 0
      ExplicitTop = 0
      ExplicitWidth = 0
      ExplicitHeight = 0
      object MemoDump: TMemo
        Left = 0
        Top = 0
        Width = 909
        Height = 504
        Align = alClient
        Color = clBtnFace
        ReadOnly = True
        ScrollBars = ssVertical
        TabOrder = 0
      end
    end
    object TSOptions: TTabSheet
      Caption = 'Options'
      ImageIndex = 7
      OnShow = OnTabSheetShow
      ExplicitLeft = 0
      ExplicitTop = 0
      ExplicitWidth = 0
      ExplicitHeight = 0
      object LBAppInfo: TLabel
        Left = 20
        Top = 8
        Width = 140
        Height = 16
        Caption = 'APP_NAME + APP_BUILD'
      end
      object CBDetectByContent: TCheckBox
        Left = 20
        Top = 40
        Width = 315
        Height = 17
        Caption = 'Detect files with unknown extension by content'
        TabOrder = 0
      end
    end
  end
  object PopupMenu: TPopupMenu
    OnPopup = PopupMenuPopup
    Left = 378
    Top = 226
    object MICopyValue: TMenuItem
      Caption = 'Copy Value'
      OnClick = MICopyValueClick
    end
    object MICopyDescr: TMenuItem
      Caption = 'Copy Description'
      OnClick = MICopyDescrClick
    end
    object MICopyNode: TMenuItem
      Caption = 'Copy Full Node'
      OnClick = MICopyNodeClick
    end
  end
end
