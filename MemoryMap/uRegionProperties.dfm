object dlgRegionProps: TdlgRegionProps
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - Region Properties'
  ClientHeight = 424
  ClientWidth = 851
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
  OnKeyPress = FormKeyPress
  PixelsPerInch = 96
  TextHeight = 13
  object edProperties: TRichEdit
    Left = 0
    Top = 0
    Width = 851
    Height = 424
    Align = alClient
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    PopupMenu = PopupMenu1
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 0
    ExplicitWidth = 709
  end
  object PopupMenu1: TPopupMenu
    Left = 376
    Top = 248
    object mnuCopy: TMenuItem
      Caption = 'Copy'
      ShortCut = 16451
      OnClick = mnuCopyClick
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
