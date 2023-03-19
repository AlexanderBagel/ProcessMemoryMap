object dlgMemoryMapListInfoSettings: TdlgMemoryMapListInfoSettings
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Process Memory Map - MemoryMap List Info Settings'
  ClientHeight = 339
  ClientWidth = 502
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
  object SpeedButton1: TSpeedButton
    Left = 471
    Top = 24
    Width = 23
    Height = 22
    Hint = 'Browse...'
    Caption = '...'
    ParentShowHint = False
    ShowHint = True
    OnClick = SpeedButton1Click
  end
  object Label1: TLabel
    Left = 32
    Top = 96
    Width = 52
    Height = 13
    Caption = 'Dump size:'
  end
  object SpeedButton2: TSpeedButton
    Left = 471
    Top = 232
    Width = 23
    Height = 22
    Hint = 'Browse...'
    Caption = '...'
    ParentShowHint = False
    ShowHint = True
    OnClick = SpeedButton2Click
  end
  object Bevel1: TBevel
    Left = 8
    Top = 152
    Width = 486
    Height = 10
    Shape = bsTopLine
  end
  object edMML: TLabeledEdit
    Left = 8
    Top = 24
    Width = 457
    Height = 21
    EditLabel.Width = 80
    EditLabel.Height = 13
    EditLabel.Caption = 'Path to MML file:'
    TabOrder = 0
  end
  object cbShowMiniDump: TCheckBox
    Left = 8
    Top = 72
    Width = 97
    Height = 17
    Caption = 'Show MiniDump'
    Checked = True
    State = cbChecked
    TabOrder = 1
  end
  object cbShowDisasm: TCheckBox
    Left = 8
    Top = 51
    Width = 97
    Height = 17
    Caption = 'Show Disasembly'
    TabOrder = 2
  end
  object cbDumpSize: TComboBox
    Left = 32
    Top = 115
    Width = 145
    Height = 21
    Style = csDropDownList
    ItemIndex = 4
    TabOrder = 3
    Text = '256'
    Items.Strings = (
      '16'
      '32'
      '64'
      '128'
      '256'
      '512'
      '1024'
      '2048'
      '4096'
      'Full Region Size')
  end
  object cbSave: TCheckBox
    Left = 8
    Top = 192
    Width = 97
    Height = 17
    Caption = 'Save Result'
    TabOrder = 4
  end
  object edSave: TLabeledEdit
    Left = 8
    Top = 232
    Width = 457
    Height = 21
    EditLabel.Width = 86
    EditLabel.Height = 13
    EditLabel.Caption = 'Path to result file:'
    TabOrder = 5
  end
  object cbSaveFullDump: TCheckBox
    Left = 32
    Top = 264
    Width = 201
    Height = 17
    Caption = 'Save Full Dump if page not Shared'
    Checked = True
    State = cbChecked
    TabOrder = 6
  end
  object Button1: TButton
    Left = 419
    Top = 305
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 7
  end
  object Button2: TButton
    Left = 338
    Top = 305
    Width = 75
    Height = 25
    Caption = 'Scan'
    Default = True
    TabOrder = 8
    OnClick = Button2Click
  end
  object cbSaveIfWrongCRC: TCheckBox
    Left = 32
    Top = 288
    Width = 201
    Height = 17
    Caption = 'Save if CRC wrong'
    Checked = True
    State = cbChecked
    TabOrder = 9
  end
  object cbGenerateMML: TCheckBox
    Left = 8
    Top = 169
    Width = 194
    Height = 17
    Caption = 'Generate MML with updated CRC'
    TabOrder = 10
  end
  object OpenMMListDialog: TOpenDialog
    DefaultExt = 'mml'
    Filter = 'MemoryMap List (*.mml)|*.mml|All Files (*.*)|*.*'
    Options = [ofHideReadOnly, ofPathMustExist, ofFileMustExist, ofEnableSizing]
    Left = 327
    Top = 80
  end
  object SaveResultDialog: TSaveDialog
    DefaultExt = 'zip'
    Filter = 'ZIP archive (*.zip)|*.zip|All Files (*.*)|*.*'
    Options = [ofOverwritePrompt, ofHideReadOnly, ofPathMustExist, ofNoReadOnlyReturn, ofEnableSizing]
    Left = 440
    Top = 80
  end
end
