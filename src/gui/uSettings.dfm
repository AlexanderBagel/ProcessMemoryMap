object dlgSettings: TdlgSettings
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Process Memory Map - Settings'
  ClientHeight = 365
  ClientWidth = 445
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
  object Button1: TButton
    Left = 362
    Top = 333
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 0
  end
  object btnOk: TButton
    Left = 281
    Top = 333
    Width = 75
    Height = 25
    Caption = 'OK'
    TabOrder = 1
    OnClick = btnOkClick
  end
  object btnReset: TButton
    Left = 8
    Top = 332
    Width = 75
    Height = 25
    Caption = 'Reset'
    TabOrder = 2
    OnClick = btnResetClick
  end
  object tvNavigate: TTreeView
    Left = 8
    Top = 8
    Width = 121
    Height = 318
    HideSelection = False
    HotTrack = True
    Indent = 19
    ReadOnly = True
    RowSelect = True
    ShowLines = False
    TabOrder = 3
    OnClick = tvNavigateClick
    Items.NodeData = {
      03040000002C0000000000000000000000FFFFFFFFFFFFFFFF00000000000000
      00000000000107470065006E006500720061006C003200000000000000000000
      00FFFFFFFFFFFFFFFF000000000000000000000000010A440065006200750067
      00200049006E0066006F00340000000000000000000000FFFFFFFFFFFFFFFF00
      0000000000000000000000010B52006100770020005300630061006E006E0065
      0072002A0000000000000000000000FFFFFFFFFFFFFFFF000000000000000000
      000000010643006F006C006F0072007300}
  end
  object pcSettings: TPageControl
    Left = 135
    Top = 8
    Width = 306
    Height = 319
    ActivePage = TabSheet1
    Style = tsButtons
    TabOrder = 4
    object TabSheet1: TTabSheet
      Caption = 'TabSheet1'
      object Label11: TLabel
        Left = 3
        Top = 145
        Width = 101
        Height = 13
        Caption = 'Stack Overflow Limit:'
      end
      object Label14: TLabel
        Left = 3
        Top = 216
        Width = 94
        Height = 13
        Caption = 'Auto refresh delay:'
      end
      object Label15: TLabel
        Left = 3
        Top = 244
        Width = 88
        Height = 13
        Caption = 'Search result limit:'
      end
      object cbSearchDiff: TCheckBox
        Left = 3
        Top = 96
        Width = 185
        Height = 17
        Caption = 'Search differences after refresh'
        TabOrder = 0
      end
      object cbShowDetailedHeapData: TCheckBox
        Left = 3
        Top = 73
        Width = 185
        Height = 17
        Caption = 'Show detailed heap'
        TabOrder = 1
      end
      object cbShowFreeRegions: TCheckBox
        Left = 3
        Top = 50
        Width = 185
        Height = 17
        Caption = 'Show free regions'
        TabOrder = 2
      end
      object cbReconnect: TCheckBox
        Left = 3
        Top = 26
        Width = 185
        Height = 17
        Caption = 'Auto Reconnect'
        TabOrder = 3
      end
      object cbSuspendProcess: TCheckBox
        Left = 3
        Top = 3
        Width = 184
        Height = 17
        Caption = 'Suspend process before scan'
        TabOrder = 4
      end
      object cbShowChildFormsOnTaskBar: TCheckBox
        Left = 3
        Top = 119
        Width = 246
        Height = 17
        Caption = 'Show Child Forms on TaskBar'
        TabOrder = 5
      end
      object seSOLimit: TSpinEdit
        Left = 110
        Top = 142
        Width = 62
        Height = 22
        MaxValue = 400
        MinValue = 1
        TabOrder = 6
        Value = 30
      end
      object cbCheckStackAddrPCExecutable: TCheckBox
        Left = 3
        Top = 167
        Width = 214
        Height = 17
        Caption = 'Check Stack AddrPC is Executable'
        TabOrder = 7
      end
      object cbAutoRefresh: TCheckBox
        Left = 3
        Top = 190
        Width = 246
        Height = 17
        Caption = 'Auto Refresh Region Data'
        TabOrder = 8
      end
      object seAutoRefreshDelay: TSpinEdit
        Left = 110
        Top = 213
        Width = 62
        Height = 22
        MaxValue = 60000
        MinValue = 200
        TabOrder = 9
        Value = 5000
      end
      object seSearchLimit: TSpinEdit
        Left = 110
        Top = 241
        Width = 62
        Height = 22
        MaxValue = 500
        MinValue = 1
        TabOrder = 10
        Value = 50
      end
    end
    object TabSheet2: TTabSheet
      Caption = 'TabSheet2'
      ImageIndex = 1
      object Label10: TLabel
        Left = 3
        Top = 130
        Width = 102
        Height = 13
        Caption = 'String minimal length:'
      end
      object Label12: TLabel
        Left = 3
        Top = 29
        Width = 101
        Height = 13
        Caption = 'Line search distance:'
      end
      object Label13: TLabel
        Left = 3
        Top = 57
        Width = 102
        Height = 13
        Caption = 'Line search direction:'
      end
      object cbLoadLineSymbols: TCheckBox
        Left = 3
        Top = 3
        Width = 278
        Height = 17
        Caption = 'Load Line Information from MAP/DWARF (if present)'
        TabOrder = 0
      end
      object cbDemangleNames: TCheckBox
        Left = 3
        Top = 81
        Width = 254
        Height = 17
        Caption = 'Demangle COFF/DWARF names'
        Checked = True
        State = cbChecked
        TabOrder = 1
      end
      object cbLoadStrings: TCheckBox
        Left = 3
        Top = 104
        Width = 190
        Height = 17
        Caption = 'Load Strings from PE Images'
        TabOrder = 2
      end
      object seStringLength: TSpinEdit
        Left = 110
        Top = 127
        Width = 60
        Height = 22
        MaxValue = 255
        MinValue = 1
        TabOrder = 3
        Value = 4
      end
      object cbShowAligns: TCheckBox
        Left = 3
        Top = 155
        Width = 174
        Height = 17
        Caption = 'Show Aligns in Disassembler'
        TabOrder = 4
      end
      object seLineLimit: TSpinEdit
        Left = 110
        Top = 26
        Width = 60
        Height = 22
        MaxValue = 1024
        MinValue = 1
        TabOrder = 5
        Value = 42
      end
      object cbLineDirection: TComboBox
        Left = 110
        Top = 54
        Width = 145
        Height = 21
        Style = csDropDownList
        ItemIndex = 0
        TabOrder = 6
        Text = 'Down (return address)'
        Items.Strings = (
          'Down (return address)'
          'Up (call address)')
      end
    end
    object TabSheet3: TTabSheet
      Caption = 'TabSheet3'
      ImageIndex = 2
      object Label9: TLabel
        Left = 3
        Top = 7
        Width = 109
        Height = 13
        Caption = 'Scanner update mode:'
      end
      object cbScannerMode: TComboBox
        Left = 118
        Top = 3
        Width = 92
        Height = 21
        Style = csDropDownList
        ItemIndex = 1
        TabOrder = 0
        Text = 'Default'
        Items.Strings = (
          'No update'
          'Default'
          'Force update')
      end
      object cbUseFilter: TCheckBox
        Left = 3
        Top = 26
        Width = 128
        Height = 17
        Hint = 
          'Hide hook at import/delayed_import to apphelp.dll and kernelbase' +
          '.dll'
        Caption = 'Use Scanner Filter'
        ParentShowHint = False
        ShowHint = True
        TabOrder = 1
      end
    end
    object TabSheet4: TTabSheet
      Caption = 'TabSheet4'
      ImageIndex = 3
      object cbShowColors: TCheckBox
        Left = 3
        Top = 3
        Width = 185
        Height = 17
        Caption = 'Show colors'
        TabOrder = 0
      end
      object GroupBox1: TGroupBox
        Left = 3
        Top = 26
        Width = 289
        Height = 249
        Caption = 'Color scheme:'
        TabOrder = 1
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
    end
  end
  object ColorDialog: TColorDialog
    Left = 56
    Top = 256
  end
end
