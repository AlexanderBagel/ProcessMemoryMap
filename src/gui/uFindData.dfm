object dlgFindData: TdlgFindData
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Process Memory Map - Search Data'
  ClientHeight = 113
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
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 16
    Top = 8
    Width = 28
    Height = 13
    Caption = 'Type:'
  end
  object Label2: TLabel
    Left = 16
    Top = 35
    Width = 26
    Height = 13
    Caption = 'Text:'
  end
  object Label4: TLabel
    Left = 16
    Top = 87
    Width = 58
    Height = 13
    Caption = 'Start (HEX):'
  end
  object btnCancel: TButton
    Left = 406
    Top = 82
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'Cancel'
    TabOrder = 0
    OnClick = btnCancelClick
  end
  object btnSearch: TButton
    Left = 325
    Top = 82
    Width = 75
    Height = 25
    Caption = 'Search'
    Default = True
    TabOrder = 1
    OnClick = btnSearchClick
  end
  object cbSkipROMem: TCheckBox
    Left = 8
    Top = 59
    Width = 66
    Height = 17
    Hint = 'Skip "read-only" memory pages'
    Caption = 'Skip RO'
    Checked = True
    ParentShowHint = False
    ShowHint = True
    State = cbChecked
    TabOrder = 2
    OnClick = cbSearchInputTypeChange
  end
  object ProgressBar: TProgressBar
    Left = 80
    Top = 59
    Width = 401
    Height = 17
    TabOrder = 3
  end
  object edStartAddr: TEdit
    Left = 80
    Top = 84
    Width = 137
    Height = 21
    TabOrder = 4
    Text = '0'
    OnChange = edStartAddrChange
  end
  object cbSearchInputType: TComboBox
    Left = 48
    Top = 5
    Width = 433
    Height = 21
    Style = csDropDownList
    TabOrder = 5
    OnChange = cbSearchInputTypeChange
  end
  object cbSearchText: TComboBox
    Left = 48
    Top = 32
    Width = 433
    Height = 21
    TabOrder = 6
    TextHint = 'Enter search pattern...'
    OnChange = cbSearchInputTypeChange
  end
end
