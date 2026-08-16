object dlgStringsViewer: TdlgStringsViewer
  Left = 0
  Top = 0
  Margins.Left = 5
  Margins.Top = 5
  Margins.Right = 5
  Margins.Bottom = 5
  ActiveControl = lvStrings
  Caption = 'Process Memory Map - Strings'
  ClientHeight = 617
  ClientWidth = 1287
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
  object lvStrings: TVirtualStringTree
    Left = 0
    Top = 0
    Width = 1287
    Height = 617
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    AccessibleName = 'Data'
    Align = alClient
    DefaultNodeHeight = 27
    Header.AutoSizeIndex = -1
    Header.Height = 28
    Header.MaxHeight = 15000
    Header.MinHeight = 15
    Header.Options = [hoAutoResize, hoColumnResize, hoDrag, hoShowSortGlyphs, hoVisible]
    Indent = 27
    Margin = 6
    PopupMenu = pmCopy
    TabOrder = 0
    TextMargin = 6
    TreeOptions.MiscOptions = [toAcceptOLEDrop, toFullRepaintOnResize, toInitOnSave, toWheelPanning, toEditOnClick]
    TreeOptions.PaintOptions = [toHideFocusRect, toShowButtons, toShowDropmark, toShowRoot, toShowVertGridLines, toThemeAware, toUseBlendedImages, toUseBlendedSelection, toUseExplorerTheme]
    TreeOptions.SelectionOptions = [toFullRowSelect]
    OnDblClick = lvStringsDblClick
    OnGetText = lvStringsGetText
    OnHeaderClick = lvStringsHeaderClick
    Touch.InteractiveGestures = [igPan, igPressAndTap]
    Touch.InteractiveGestureOptions = [igoPanSingleFingerHorizontal, igoPanSingleFingerVertical, igoPanInertia, igoPanGutter, igoParentPassthrough]
    Columns = <
      item
        MaxWidth = 15000
        MinWidth = 15
        Position = 0
        Spacing = 5
        Text = 'Address'
        Width = 188
      end
      item
        MaxWidth = 15000
        MinWidth = 15
        Position = 1
        Spacing = 5
        Text = 'Module'
        Width = 300
      end
      item
        MaxWidth = 15000
        MinWidth = 15
        Position = 2
        Spacing = 5
        Text = 'Type'
        Width = 113
      end
      item
        MaxWidth = 15000
        MinWidth = 15
        Position = 3
        Spacing = 5
        Text = 'Data'
        Width = 682
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
    object mnuOpenInExplorer: TMenuItem
      Caption = 'Open In Explorer'
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
      Caption = 'Copy String'
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
