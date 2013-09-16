object dlgFindData: TdlgFindData
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Process Memory Map - Search Data'
  ClientHeight = 218
  ClientWidth = 489
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poMainFormCenter
  OnClose = FormClose
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 16
    Top = 11
    Width = 28
    Height = 13
    Caption = 'ASCII'
  end
  object Label2: TLabel
    Left = 16
    Top = 38
    Width = 46
    Height = 13
    Caption = 'UNICODE'
  end
  object Label3: TLabel
    Left = 16
    Top = 67
    Width = 19
    Height = 13
    Caption = 'HEX'
  end
  object Label4: TLabel
    Left = 16
    Top = 187
    Width = 58
    Height = 13
    Caption = 'Start (HEX):'
  end
  object edAnsi: TEdit
    Left = 80
    Top = 8
    Width = 401
    Height = 21
    TabOrder = 0
    OnChange = edAnsiChange
  end
  object edUnicode: TEdit
    Left = 80
    Top = 35
    Width = 401
    Height = 21
    TabOrder = 1
    OnChange = edUnicodeChange
  end
  object edHex: TMemo
    Left = 80
    Top = 64
    Width = 401
    Height = 89
    TabOrder = 2
    OnChange = edHexChange
    OnKeyPress = edHexKeyPress
  end
  object btnCancel: TButton
    Left = 406
    Top = 182
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'Cancel'
    TabOrder = 3
    OnClick = btnCancelClick
  end
  object btnSearch: TButton
    Left = 325
    Top = 182
    Width = 75
    Height = 25
    Caption = 'Search'
    Default = True
    TabOrder = 4
    OnClick = btnSearchClick
  end
  object cbSkipROMem: TCheckBox
    Left = 8
    Top = 159
    Width = 66
    Height = 17
    Hint = 'Skip "read-only" memory pages'
    Caption = 'Skip RO'
    Checked = True
    ParentShowHint = False
    ShowHint = True
    State = cbChecked
    TabOrder = 5
  end
  object ProgressBar: TProgressBar
    Left = 80
    Top = 159
    Width = 401
    Height = 17
    TabOrder = 6
  end
  object btnSearchNext: TButton
    Left = 232
    Top = 182
    Width = 87
    Height = 25
    Caption = 'Search Next >'
    Enabled = False
    TabOrder = 7
    OnClick = btnSearchNextClick
  end
  object edStartAddr: TEdit
    Left = 80
    Top = 184
    Width = 137
    Height = 21
    TabOrder = 8
    Text = '0'
    OnChange = edStartAddrChange
    OnKeyPress = edHexKeyPress
  end
end
