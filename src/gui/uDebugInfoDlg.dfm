object dlgDbgInfo: TdlgDbgInfo
  Left = 0
  Top = 0
  Margins.Left = 5
  Margins.Top = 5
  Margins.Right = 5
  Margins.Bottom = 5
  Caption = 'Process Memory Map - Debug Info'
  ClientHeight = 626
  ClientWidth = 1190
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -17
  Font.Name = 'Tahoma'
  Font.Style = []
  KeyPreview = True
  Position = poMainFormCenter
  PixelsPerInch = 144
  TextHeight = 21
  object edDebugInfo: TRichEdit
    Left = 0
    Top = 0
    Width = 1190
    Height = 626
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Align = alClient
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -17
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
    PopupMenu = PopupMenu1
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 0
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
