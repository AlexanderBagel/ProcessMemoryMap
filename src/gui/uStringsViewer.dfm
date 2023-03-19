object dlgStringsViewer: TdlgStringsViewer
  Left = 0
  Top = 0
  ActiveControl = lvStrings
  Caption = 'Process Memory Map - Strings'
  ClientHeight = 411
  ClientWidth = 852
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
  object lvStrings: TVirtualStringTree
    Left = 0
    Top = 0
    Width = 852
    Height = 411
    AccessibleName = 'Data'
    Align = alClient
    Header.AutoSizeIndex = -1
    Header.Height = 24
    Header.Options = [hoAutoResize, hoColumnResize, hoDrag, hoShowSortGlyphs, hoVisible]
    PopupMenu = pmCopy
    TabOrder = 0
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
        Position = 0
        Text = 'Address'
        Width = 125
      end
      item
        Position = 1
        Text = 'Module'
        Width = 200
      end
      item
        Position = 2
        Text = 'Type'
        Width = 75
      end
      item
        Position = 3
        Text = 'Data'
        Width = 448
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
