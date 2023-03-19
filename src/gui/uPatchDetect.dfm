object dlgPatches: TdlgPatches
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - Hook Scanner'
  ClientHeight = 548
  ClientWidth = 1112
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
  object edLog: TRichEdit
    Left = 0
    Top = 0
    Width = 1112
    Height = 548
    Align = alClient
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    PopupMenu = mnuPopup
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 0
    Zoom = 100
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
    object N1: TMenuItem
      Caption = '-'
    end
    object mnuRefresh: TMenuItem
      Caption = 'Refresh'
      ShortCut = 116
    end
  end
end
