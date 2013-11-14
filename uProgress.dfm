object dlgProgress: TdlgProgress
  Left = 0
  Top = 0
  BorderStyle = bsNone
  Caption = 'dlgProgress'
  ClientHeight = 67
  ClientWidth = 465
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poMainFormCenter
  PixelsPerInch = 96
  TextHeight = 13
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 465
    Height = 67
    Align = alClient
    TabOrder = 0
    object lblProgress: TLabel
      Left = 16
      Top = 16
      Width = 433
      Height = 13
      AutoSize = False
      Caption = 'lblProgress'
      EllipsisPosition = epPathEllipsis
    end
    object ProgressBar: TProgressBar
      Left = 16
      Top = 35
      Width = 433
      Height = 17
      TabOrder = 0
    end
  end
end
