object dlgSettings: TdlgSettings
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Process Memory Map - Settings'
  ClientHeight = 412
  ClientWidth = 318
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poMainFormCenter
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object cbShowFreeRegions: TCheckBox
    Left = 16
    Top = 31
    Width = 185
    Height = 17
    Caption = 'Show free regions'
    TabOrder = 0
  end
  object cbShowColors: TCheckBox
    Left = 16
    Top = 100
    Width = 185
    Height = 17
    Caption = 'Show colors'
    TabOrder = 1
  end
  object GroupBox1: TGroupBox
    Left = 16
    Top = 123
    Width = 289
    Height = 249
    Caption = 'Color scheme:'
    TabOrder = 2
    object Label1: TLabel
      Left = 38
      Top = 24
      Width = 60
      Height = 13
      Alignment = taRightJustify
      Caption = 'Image color:'
    end
    object Label2: TLabel
      Left = 34
      Top = 80
      Width = 64
      Height = 13
      Alignment = taRightJustify
      Caption = 'Private color:'
    end
    object Label3: TLabel
      Left = 20
      Top = 108
      Width = 78
      Height = 13
      Alignment = taRightJustify
      Caption = 'Shareable color:'
    end
    object Label4: TLabel
      Left = 13
      Top = 136
      Width = 85
      Height = 13
      Alignment = taRightJustify
      Caption = 'Mapped file color:'
    end
    object Label5: TLabel
      Left = 43
      Top = 164
      Width = 55
      Height = 13
      Alignment = taRightJustify
      Caption = 'Heap color:'
    end
    object Label6: TLabel
      Left = 9
      Top = 192
      Width = 89
      Height = 13
      Alignment = taRightJustify
      Caption = 'Thread data color:'
    end
    object Label7: TLabel
      Left = 33
      Top = 220
      Width = 65
      Height = 13
      Alignment = taRightJustify
      Caption = 'System color:'
    end
    object Label8: TLabel
      Left = 15
      Top = 52
      Width = 83
      Height = 13
      Alignment = taRightJustify
      Caption = 'Image part color:'
    end
    object pnImage0: TPanel
      Left = 104
      Top = 21
      Width = 169
      Height = 22
      Color = clMedGray
      ParentBackground = False
      TabOrder = 0
      OnClick = pnImage0Click
    end
    object pnImage1: TPanel
      Tag = 1
      Left = 104
      Top = 49
      Width = 169
      Height = 22
      Color = clMedGray
      ParentBackground = False
      TabOrder = 1
      OnClick = pnImage0Click
    end
    object pnImage2: TPanel
      Tag = 2
      Left = 104
      Top = 77
      Width = 169
      Height = 22
      Color = clMedGray
      ParentBackground = False
      TabOrder = 2
      OnClick = pnImage0Click
    end
    object pnImage3: TPanel
      Tag = 3
      Left = 104
      Top = 105
      Width = 169
      Height = 22
      Color = clMedGray
      ParentBackground = False
      TabOrder = 3
      OnClick = pnImage0Click
    end
    object pnImage4: TPanel
      Tag = 4
      Left = 104
      Top = 133
      Width = 169
      Height = 22
      Color = clMedGray
      ParentBackground = False
      TabOrder = 4
      OnClick = pnImage0Click
    end
    object pnImage5: TPanel
      Tag = 5
      Left = 104
      Top = 161
      Width = 169
      Height = 22
      Color = clMedGray
      ParentBackground = False
      TabOrder = 5
      OnClick = pnImage0Click
    end
    object pnImage6: TPanel
      Tag = 6
      Left = 104
      Top = 189
      Width = 169
      Height = 22
      Color = clMedGray
      ParentBackground = False
      TabOrder = 6
      OnClick = pnImage0Click
    end
    object pnImage7: TPanel
      Tag = 7
      Left = 104
      Top = 217
      Width = 169
      Height = 22
      Color = clMedGray
      ParentBackground = False
      TabOrder = 7
      OnClick = pnImage0Click
    end
  end
  object Button1: TButton
    Left = 230
    Top = 378
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 3
  end
  object btnOk: TButton
    Left = 149
    Top = 378
    Width = 75
    Height = 25
    Caption = 'OK'
    TabOrder = 4
    OnClick = btnOkClick
  end
  object btnReset: TButton
    Left = 16
    Top = 378
    Width = 75
    Height = 25
    Caption = 'Reset'
    TabOrder = 5
    OnClick = btnResetClick
  end
  object cbSearchDiff: TCheckBox
    Left = 16
    Top = 77
    Width = 185
    Height = 17
    Caption = 'Search differences after refresh'
    TabOrder = 6
  end
  object cbShowDetailedHeapData: TCheckBox
    Left = 16
    Top = 54
    Width = 185
    Height = 17
    Caption = 'Show detailed heap'
    TabOrder = 7
  end
  object cbSuspendProcess: TCheckBox
    Left = 17
    Top = 8
    Width = 184
    Height = 17
    Caption = 'Suspend process before scan'
    TabOrder = 8
  end
  object ColorDialog: TColorDialog
    Left = 232
    Top = 8
  end
end
