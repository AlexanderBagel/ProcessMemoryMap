object dlgExportList: TdlgExportList
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - Exports'
  ClientHeight = 337
  ClientWidth = 704
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  KeyPreview = True
  OldCreateOrder = False
  Position = poMainFormCenter
  OnClose = FormClose
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  OnKeyPress = FormKeyPress
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 13
  object lvExports: TVirtualStringTree
    Left = 0
    Top = 0
    Width = 704
    Height = 337
    Align = alClient
    Header.AutoSizeIndex = 2
    Header.DefaultHeight = 21
    Header.Font.Charset = DEFAULT_CHARSET
    Header.Font.Color = clWindowText
    Header.Font.Height = -11
    Header.Font.Name = 'Tahoma'
    Header.Font.Style = []
    Header.Height = 21
    Header.Options = [hoAutoResize, hoColumnResize, hoDrag, hoShowSortGlyphs, hoVisible]
    PopupMenu = pmCopy
    TabOrder = 0
    TreeOptions.AutoOptions = [toAutoDropExpand, toAutoScrollOnExpand, toAutoSort, toAutoTristateTracking, toAutoDeleteMovedNodes]
    TreeOptions.PaintOptions = [toHideFocusRect, toShowButtons, toShowDropmark, toShowRoot, toShowVertGridLines, toThemeAware, toUseBlendedImages, toUseBlendedSelection, toUseExplorerTheme]
    TreeOptions.SelectionOptions = [toFullRowSelect]
    OnDblClick = lvExportsDblClick
    OnGetText = lvExportsGetText
    OnHeaderClick = lvExportsHeaderClick
    ExplicitWidth = 635
    Columns = <
      item
        Position = 0
        Width = 100
        WideText = 'Type'
      end
      item
        Position = 1
        Width = 150
        WideText = 'Address'
      end
      item
        Position = 2
        Width = 123
        WideText = 'Module'
      end
      item
        Options = [coAllowClick, coDraggable, coEnabled, coParentBidiMode, coParentColor, coResizable, coShowDropMark, coVisible, coAutoSpring, coAllowFocus]
        Position = 3
        Width = 331
        WideText = 'Function'
      end>
  end
  object pmCopy: TPopupMenu
    Left = 32
    Top = 32
    object mnuGotoAddress: TMenuItem
      Caption = 'Go to Address'
      Default = True
      ShortCut = 13
      OnClick = mnuGotoAddressClick
    end
    object mnuSeparator1: TMenuItem
      Caption = '-'
    end
    object mnuCopyAddress: TMenuItem
      Caption = 'Copy Address'
      OnClick = mnuCopyAddressClick
    end
    object mnuCopyFunctionName: TMenuItem
      Caption = 'Copy Function Name'
      OnClick = mnuCopyFunctionNameClick
    end
    object mnuCopyLine: TMenuItem
      Caption = 'Copy Line'
      OnClick = mnuCopyLineClick
    end
    object mnuSeparator2: TMenuItem
      Caption = '-'
    end
    object mnuNextMatch: TMenuItem
      Caption = 'Next Match'
      ShortCut = 114
      OnClick = mnuNextMatchClick
    end
  end
end
