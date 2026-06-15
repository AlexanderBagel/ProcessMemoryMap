object dlgFindData: TdlgFindData
  Left = 0
  Top = 0
  Margins.Left = 5
  Margins.Top = 5
  Margins.Right = 5
  Margins.Bottom = 5
  BorderStyle = bsDialog
  Caption = 'Process Memory Map - Search Data'
  ClientHeight = 170
  ClientWidth = 743
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -17
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poMainFormCenter
  OnClose = FormClose
  OnCreate = FormCreate
  OnShow = FormShow
  PixelsPerInch = 144
  DesignSize = (
    743
    170)
  TextHeight = 21
  object Label1: TLabel
    Left = 24
    Top = 12
    Width = 42
    Height = 21
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'Type:'
  end
  object Label2: TLabel
    Left = 24
    Top = 53
    Width = 39
    Height = 21
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'Text:'
  end
  object Label4: TLabel
    Left = 24
    Top = 131
    Width = 92
    Height = 21
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'Start (HEX):'
  end
  object btnHelp: TSpeedButton
    Left = 693
    Top = 48
    Width = 29
    Height = 29
    Anchors = [akTop, akRight]
    Caption = '?'
    OnClick = btnHelpClick
  end
  object btnCancel: TButton
    Left = 609
    Top = 123
    Width = 113
    Height = 38
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Cancel = True
    Caption = 'Cancel'
    TabOrder = 0
    OnClick = btnCancelClick
  end
  object btnSearch: TButton
    Left = 488
    Top = 123
    Width = 112
    Height = 38
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'Search'
    Default = True
    TabOrder = 1
    OnClick = btnSearchClick
  end
  object cbSkipROMem: TCheckBox
    Left = 12
    Top = 89
    Width = 99
    Height = 25
    Hint = 'Skip "read-only" memory pages'
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'Skip RO'
    Checked = True
    ParentShowHint = False
    ShowHint = True
    State = cbChecked
    TabOrder = 2
    OnClick = cbSearchInputTypeChange
  end
  object edStartAddr: TEdit
    Left = 120
    Top = 126
    Width = 206
    Height = 29
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    TabOrder = 3
    Text = '0'
    OnChange = edStartAddrChange
  end
  object cbSearchInputType: TComboBox
    Left = 72
    Top = 8
    Width = 650
    Height = 29
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Style = csDropDownList
    TabOrder = 4
    OnChange = cbSearchInputTypeChange
  end
  object cbSearchText: TComboBox
    Left = 72
    Top = 48
    Width = 613
    Height = 29
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    TabOrder = 5
    TextHint = 'Enter search pattern...'
    OnChange = cbSearchInputTypeChange
  end
  object pnProgress: TPanel
    Left = 120
    Top = 89
    Width = 602
    Height = 25
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    BevelOuter = bvNone
    TabOrder = 6
  end
end
