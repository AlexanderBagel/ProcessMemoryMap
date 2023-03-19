object dlgDbgInfo: TdlgDbgInfo
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - Debug Info'
  ClientHeight = 417
  ClientWidth = 793
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  KeyPreview = True
  OldCreateOrder = False
  Position = poMainFormCenter
  OnKeyPress = FormKeyPress
  PixelsPerInch = 96
  TextHeight = 13
  object edDebugInfo: TRichEdit
    Left = 0
    Top = 0
    Width = 793
    Height = 417
    Align = alClient
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
    PopupMenu = PopupMenu1
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 0
    Zoom = 100
  end
  object PopupMenu1: TPopupMenu
    Left = 272
    Top = 96
    object Copyselected1: TMenuItem
      Caption = 'Copy selected'
      OnClick = Copyselected1Click
    end
    object Copydebuginfointoclipboard1: TMenuItem
      Caption = 'Copy debug info into clipboard'
      OnClick = Copydebuginfointoclipboard1Click
    end
  end
end
