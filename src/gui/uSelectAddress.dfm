object dlgSelectAddress: TdlgSelectAddress
  Left = 0
  Top = 0
  Margins.Left = 5
  Margins.Top = 5
  Margins.Right = 5
  Margins.Bottom = 5
  BorderStyle = bsDialog
  Caption = 'Process Memory Map - Query Address'
  ClientHeight = 195
  ClientWidth = 491
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -17
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poMainFormCenter
  PixelsPerInch = 144
  TextHeight = 21
  object Label1: TLabel
    Left = 24
    Top = 24
    Width = 175
    Height = 21
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'Enter address to query:'
  end
  object Label2: TLabel
    Left = 48
    Top = 60
    Width = 27
    Height = 21
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'INT'
  end
  object lblHex: TLabel
    Left = 39
    Top = 101
    Width = 31
    Height = 21
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'HEX'
  end
  object lblSizeInt: TLabel
    Left = 48
    Top = 162
    Width = 27
    Height = 21
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'INT'
    Visible = False
  end
  object lblSize: TLabel
    Left = 24
    Top = 132
    Width = 80
    Height = 21
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'Enter size:'
    Visible = False
  end
  object edInt: TEdit
    Left = 81
    Top = 56
    Width = 380
    Height = 29
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    TabOrder = 1
    Text = '0'
    OnChange = edIntChange
    OnKeyPress = edIntKeyPress
  end
  object edHex: TEdit
    Left = 81
    Top = 96
    Width = 380
    Height = 29
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    TabOrder = 0
    Text = '0'
    OnChange = edHexChange
  end
  object btnCancel: TButton
    Left = 348
    Top = 149
    Width = 113
    Height = 37
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 2
  end
  object btnOk: TButton
    Left = 227
    Top = 149
    Width = 112
    Height = 37
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'OK'
    Default = True
    ModalResult = 1
    TabOrder = 3
  end
  object edSize: TEdit
    Left = 81
    Top = 158
    Width = 380
    Height = 29
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    TabOrder = 4
    Text = '0'
    Visible = False
    OnChange = edIntChange
    OnKeyPress = edIntKeyPress
  end
end
