object dlgPatches: TdlgPatches
  Left = 0
  Top = 0
  Margins.Left = 5
  Margins.Top = 5
  Margins.Right = 5
  Margins.Bottom = 5
  Caption = 'Process Memory Map - Hook Scanner'
  ClientHeight = 770
  ClientWidth = 1547
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -17
  Font.Name = 'Tahoma'
  Font.Style = []
  KeyPreview = True
  Position = poMainFormCenter
  OnClose = FormClose
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  OnKeyPress = FormKeyPress
  OnShow = FormShow
  PixelsPerInch = 144
  TextHeight = 21
  object edLog: TRichEdit
    Left = 0
    Top = 0
    Width = 1547
    Height = 770
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Align = alClient
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -17
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    PopupMenu = mnuPopup
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 0
  end
  object mnuPopup: TPopupMenu
    OnPopup = mnuPopupPopup
    Left = 8
    Top = 8
    object mnuGotoAddress: TMenuItem
      Caption = 'Go to Address...'
      Default = True
      ShortCut = 13
      OnClick = mnuGotoAddressClick
    end
    object N3: TMenuItem
      Caption = '-'
    end
    object mnuCopy: TMenuItem
      Caption = 'Copy'
      ShortCut = 16451
      OnClick = mnuCopyClick
    end
    object SelectAll1: TMenuItem
      Caption = 'Select All'
      ShortCut = 16449
      OnClick = SelectAll1Click
    end
    object N2: TMenuItem
      Caption = '-'
    end
    object Restore1: TMenuItem
      Caption = 'Restore...'
      OnClick = Restore1Click
    end
    object N1: TMenuItem
      Caption = '-'
    end
    object mnuRefresh: TMenuItem
      Caption = 'Refresh'
      ShortCut = 116
      OnClick = mnuRefreshClick
    end
  end
end
