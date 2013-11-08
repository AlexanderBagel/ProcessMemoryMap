object dlgSelectAddress: TdlgSelectAddress
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Process Memory Map - Query Address'
  ClientHeight = 130
  ClientWidth = 321
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
  object Label1: TLabel
    Left = 16
    Top = 16
    Width = 115
    Height = 13
    Caption = 'Enter address to query:'
  end
  object Label2: TLabel
    Left = 32
    Top = 40
    Width = 17
    Height = 13
    Caption = 'INT'
  end
  object Label3: TLabel
    Left = 26
    Top = 67
    Width = 19
    Height = 13
    Caption = 'HEX'
  end
  object lblSizeInt: TLabel
    Left = 32
    Top = 108
    Width = 17
    Height = 13
    Caption = 'INT'
    Visible = False
  end
  object lblSize: TLabel
    Left = 16
    Top = 88
    Width = 51
    Height = 13
    Caption = 'Enter size:'
    Visible = False
  end
  object edInt: TEdit
    Left = 54
    Top = 37
    Width = 253
    Height = 21
    TabOrder = 1
    Text = '0'
    OnChange = edIntChange
    OnKeyPress = edIntKeyPress
  end
  object edHex: TEdit
    Left = 54
    Top = 64
    Width = 253
    Height = 21
    TabOrder = 0
    Text = '0'
    OnChange = edHexChange
    OnKeyPress = edHexKeyPress
  end
  object btnCancel: TButton
    Left = 232
    Top = 99
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 2
  end
  object btnOk: TButton
    Left = 151
    Top = 99
    Width = 75
    Height = 25
    Caption = 'OK'
    Default = True
    ModalResult = 1
    TabOrder = 3
  end
  object edSize: TEdit
    Left = 54
    Top = 105
    Width = 253
    Height = 21
    TabOrder = 4
    Text = '0'
    Visible = False
    OnChange = edIntChange
    OnKeyPress = edIntKeyPress
  end
end
