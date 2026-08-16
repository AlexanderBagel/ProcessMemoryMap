object dlgExportList: TdlgExportList
  Left = 0
  Top = 0
  Margins.Left = 5
  Margins.Top = 5
  Margins.Right = 5
  Margins.Bottom = 5
  ActiveControl = lvExports
  Caption = 'Process Memory Map - Exports'
  ClientHeight = 506
  ClientWidth = 1056
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -17
  Font.Name = 'Tahoma'
  Font.Style = []
  KeyPreview = True
  Position = poMainFormCenter
  OnAfterMonitorDpiChanged = FormAfterMonitorDpiChanged
  OnClose = FormClose
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  OnKeyPress = FormKeyPress
  OnShow = FormShow
  PixelsPerInch = 144
  TextHeight = 21
  object lvExports: TVirtualStringTree
    Left = 0
    Top = 0
    Width = 1056
    Height = 506
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Align = alClient
    DefaultNodeHeight = 27
    Header.AutoSizeIndex = 3
    Header.Height = 28
    Header.MaxHeight = 15000
    Header.MinHeight = 15
    Header.Options = [hoAutoResize, hoColumnResize, hoDrag, hoShowSortGlyphs, hoVisible]
    Indent = 27
    Margin = 6
    PopupMenu = pmCopy
    TabOrder = 0
    TextMargin = 6
    TreeOptions.PaintOptions = [toHideFocusRect, toShowButtons, toShowDropmark, toShowRoot, toShowVertGridLines, toThemeAware, toUseBlendedImages, toUseBlendedSelection, toUseExplorerTheme]
    TreeOptions.SelectionOptions = [toFullRowSelect]
    OnBeforeItemErase = lvExportsBeforeItemErase
    OnDblClick = lvExportsDblClick
    OnGetText = lvExportsGetText
    OnHeaderClick = lvExportsHeaderClick
    Touch.InteractiveGestures = [igPan, igPressAndTap]
    Touch.InteractiveGestureOptions = [igoPanSingleFingerHorizontal, igoPanSingleFingerVertical, igoPanInertia, igoPanGutter, igoParentPassthrough]
    Columns = <
      item
        MaxWidth = 15000
        MinWidth = 15
        Position = 0
        Spacing = 5
        Text = 'Type'
        Width = 177
      end
      item
        MaxWidth = 15000
        MinWidth = 15
        Position = 1
        Spacing = 5
        Text = 'Address'
        Width = 225
      end
      item
        MaxWidth = 15000
        MinWidth = 15
        Position = 2
        Spacing = 5
        Text = 'Module'
        Width = 204
      end
      item
        MaxWidth = 15000
        MinWidth = 15
        Options = [coAllowClick, coDraggable, coEnabled, coParentBidiMode, coParentColor, coResizable, coShowDropMark, coVisible, coAutoSpring, coAllowFocus]
        Position = 3
        Spacing = 5
        Text = 'Function'
        Width = 446
      end>
  end
  object pmCopy: TPopupMenu
    OnPopup = pmCopyPopup
    Left = 32
    Top = 32
    object mnuGotoAddress: TMenuItem
      Caption = 'Go to Address'
      Default = True
      ShortCut = 13
      OnClick = mnuGotoAddressClick
    end
    object mnuOpenInExplorer: TMenuItem
      Caption = 'Open in Explorer'
      OnClick = mnuOpenInExplorerClick
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
    object N1: TMenuItem
      Caption = '-'
    end
    object Filter1: TMenuItem
      Caption = 'Filter'
      object mnuShowEXPORT: TMenuItem
        AutoCheck = True
        Caption = 'EXPORT'
        Checked = True
        OnClick = mnuShowDWARFDATAClick
      end
      object mnuShowFORWARDED: TMenuItem
        Tag = 1
        AutoCheck = True
        Caption = 'FORWARDED'
        Checked = True
        OnClick = mnuShowDWARFDATAClick
      end
      object mnuShowREBASED: TMenuItem
        Tag = 2
        AutoCheck = True
        Caption = 'REBASED'
        Checked = True
        OnClick = mnuShowDWARFDATAClick
      end
      object mnuShowDATA: TMenuItem
        Tag = 3
        AutoCheck = True
        Caption = 'DATA'
        Checked = True
        OnClick = mnuShowDWARFDATAClick
      end
      object mnuShowINVALID: TMenuItem
        Tag = 4
        AutoCheck = True
        Caption = 'INVALID'
        Checked = True
        OnClick = mnuShowDWARFDATAClick
      end
      object mnuShowDEBUGMAPFUNC: TMenuItem
        Tag = 5
        AutoCheck = True
        Caption = 'DEBUG_MAP FUNC'
        Checked = True
        OnClick = mnuShowDWARFDATAClick
      end
      object mnuShowDEBUGMAPDATA: TMenuItem
        Tag = 6
        AutoCheck = True
        Caption = 'DEBUG_MAP DATA'
        Checked = True
        OnClick = mnuShowDWARFDATAClick
      end
      object mnuShowCOFFFUNC: TMenuItem
        Tag = 7
        AutoCheck = True
        Caption = 'COFF FUNC'
        Checked = True
        OnClick = mnuShowDWARFDATAClick
      end
      object mnuShowCOFFDATA: TMenuItem
        Tag = 8
        AutoCheck = True
        Caption = 'COFF DATA'
        Checked = True
        OnClick = mnuShowDWARFDATAClick
      end
      object mnuShowDWARFFUNC: TMenuItem
        Tag = 9
        AutoCheck = True
        Caption = 'DWARF FUNC'
        Checked = True
        OnClick = mnuShowDWARFDATAClick
      end
      object mnuShowDWARFDATA: TMenuItem
        Tag = 10
        AutoCheck = True
        Caption = 'DWARF DATA'
        Checked = True
        OnClick = mnuShowDWARFDATAClick
      end
    end
  end
end
