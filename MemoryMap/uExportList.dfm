object dlgExportList: TdlgExportList
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - Exports'
  ClientHeight = 337
  ClientWidth = 635
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
  OnKeyPress = FormKeyPress
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 13
  object lvExports: TVirtualStringTree
    Left = 0
    Top = 0
    Width = 635
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
    OnGetText = lvExportsGetText
    OnHeaderClick = lvExportsHeaderClick
    Columns = <
      item
        Position = 0
        Width = 150
        WideText = 'Address'
      end
      item
        Position = 1
        Width = 100
        WideText = 'Module'
      end
      item
        Options = [coAllowClick, coDraggable, coEnabled, coParentBidiMode, coParentColor, coResizable, coShowDropMark, coVisible, coAutoSpring, coAllowFocus]
        Position = 2
        Width = 385
        WideText = 'Function'
      end>
  end
  object pmCopy: TPopupMenu
    Left = 32
    Top = 32
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
  end
end
