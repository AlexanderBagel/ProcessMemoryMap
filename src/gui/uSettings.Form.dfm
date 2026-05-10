object dlgSettings: TdlgSettings
  Left = 0
  Top = 0
  Margins.Left = 5
  Margins.Top = 5
  Margins.Right = 5
  Margins.Bottom = 5
  BorderStyle = bsDialog
  Caption = 'Process Memory Map - Settings'
  ClientHeight = 548
  ClientWidth = 668
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -17
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poMainFormCenter
  OnCreate = FormCreate
  PixelsPerInch = 144
  TextHeight = 21
  object Button1: TButton
    Left = 543
    Top = 500
    Width = 113
    Height = 37
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 0
  end
  object btnOk: TButton
    Left = 422
    Top = 500
    Width = 112
    Height = 37
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'OK'
    TabOrder = 1
    OnClick = btnOkClick
  end
  object btnReset: TButton
    Left = 12
    Top = 498
    Width = 113
    Height = 38
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'Reset'
    TabOrder = 2
    OnClick = btnResetClick
  end
  object tvNavigate: TTreeView
    Left = 12
    Top = 12
    Width = 182
    Height = 477
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    HideSelection = False
    HotTrack = True
    Indent = 29
    ReadOnly = True
    RowSelect = True
    ShowLines = False
    TabOrder = 3
    OnClick = tvNavigateClick
    Items.NodeData = {
      070400000009540054007200650065004E006F00640065002D00000000000000
      00000000FFFFFFFFFFFFFFFF000000000000000000000000000107470065006E
      006500720061006C000000330000000000000000000000FFFFFFFFFFFFFFFF00
      000000000000000000000000010A44006500620075006700200049006E006600
      6F000000350000000000000000000000FFFFFFFFFFFFFFFF0000000000000000
      0000000000010B52006100770020005300630061006E006E006500720000002B
      0000000000000000000000FFFFFFFFFFFFFFFF00000000000000000000000000
      010643006F006C006F0072007300}
  end
  object pcSettings: TPageControl
    Left = 203
    Top = 12
    Width = 459
    Height = 479
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    ActivePage = TabSheet1
    Style = tsButtons
    TabOrder = 4
    object TabSheet1: TTabSheet
      Margins.Left = 5
      Margins.Top = 5
      Margins.Right = 5
      Margins.Bottom = 5
      Caption = 'TabSheet1'
      object Label11: TLabel
        Left = 5
        Top = 218
        Width = 158
        Height = 21
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Stack Overflow Limit:'
      end
      object Label14: TLabel
        Left = 5
        Top = 324
        Width = 142
        Height = 21
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Auto refresh delay:'
      end
      object Label15: TLabel
        Left = 5
        Top = 366
        Width = 140
        Height = 21
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Search result limit:'
      end
      object cbSearchDiff: TCheckBox
        Left = 5
        Top = 144
        Width = 277
        Height = 26
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Search differences after refresh'
        TabOrder = 0
      end
      object cbShowDetailedHeapData: TCheckBox
        Left = 5
        Top = 110
        Width = 277
        Height = 25
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Show detailed heap'
        TabOrder = 1
      end
      object cbShowFreeRegions: TCheckBox
        Left = 5
        Top = 75
        Width = 277
        Height = 26
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Show free regions'
        TabOrder = 2
      end
      object cbReconnect: TCheckBox
        Left = 5
        Top = 39
        Width = 277
        Height = 26
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Auto Reconnect'
        TabOrder = 3
      end
      object cbSuspendProcess: TCheckBox
        Left = 5
        Top = 5
        Width = 276
        Height = 25
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Suspend process before scan'
        TabOrder = 4
      end
      object cbShowChildFormsOnTaskBar: TCheckBox
        Left = 5
        Top = 179
        Width = 369
        Height = 25
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Show Child Forms on TaskBar'
        TabOrder = 5
      end
      object seSOLimit: TSpinEdit
        Left = 165
        Top = 213
        Width = 93
        Height = 32
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        MaxValue = 400
        MinValue = 1
        TabOrder = 6
        Value = 30
      end
      object cbCheckStackAddrPCExecutable: TCheckBox
        Left = 5
        Top = 251
        Width = 321
        Height = 25
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Check Stack AddrPC is Executable'
        TabOrder = 7
      end
      object cbAutoRefresh: TCheckBox
        Left = 5
        Top = 285
        Width = 369
        Height = 26
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Auto Refresh Region Data'
        TabOrder = 8
      end
      object seAutoRefreshDelay: TSpinEdit
        Left = 165
        Top = 320
        Width = 93
        Height = 32
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        MaxValue = 60000
        MinValue = 200
        TabOrder = 9
        Value = 5000
      end
      object seSearchLimit: TSpinEdit
        Left = 165
        Top = 362
        Width = 93
        Height = 32
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        MaxValue = 500
        MinValue = 1
        TabOrder = 10
        Value = 50
      end
    end
    object TabSheet2: TTabSheet
      Margins.Left = 5
      Margins.Top = 5
      Margins.Right = 5
      Margins.Bottom = 5
      Caption = 'TabSheet2'
      ImageIndex = 1
      object Label10: TLabel
        Left = 5
        Top = 195
        Width = 163
        Height = 21
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'String minimal length:'
      end
      object Label12: TLabel
        Left = 5
        Top = 44
        Width = 157
        Height = 21
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Line search distance:'
      end
      object Label13: TLabel
        Left = 5
        Top = 86
        Width = 159
        Height = 21
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Line search direction:'
      end
      object cbLoadLineSymbols: TCheckBox
        Left = 5
        Top = 5
        Width = 417
        Height = 25
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Load Line Information from MAP/DWARF (if present)'
        TabOrder = 0
      end
      object cbDemangleNames: TCheckBox
        Left = 5
        Top = 122
        Width = 381
        Height = 25
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Demangle COFF/DWARF names'
        Checked = True
        State = cbChecked
        TabOrder = 1
      end
      object cbLoadStrings: TCheckBox
        Left = 5
        Top = 156
        Width = 285
        Height = 26
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Load Strings from PE Images'
        TabOrder = 2
      end
      object seStringLength: TSpinEdit
        Left = 165
        Top = 191
        Width = 90
        Height = 29
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        MaxValue = 255
        MinValue = 1
        TabOrder = 3
        Value = 4
      end
      object cbShowAligns: TCheckBox
        Left = 5
        Top = 233
        Width = 261
        Height = 25
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Show Aligns in Disassembler'
        TabOrder = 4
      end
      object seLineLimit: TSpinEdit
        Left = 165
        Top = 39
        Width = 90
        Height = 29
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        MaxValue = 1024
        MinValue = 1
        TabOrder = 5
        Value = 42
      end
      object cbLineDirection: TComboBox
        Left = 165
        Top = 81
        Width = 218
        Height = 21
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
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
      Margins.Left = 5
      Margins.Top = 5
      Margins.Right = 5
      Margins.Bottom = 5
      Caption = 'TabSheet3'
      ImageIndex = 2
      object Label9: TLabel
        Left = 5
        Top = 11
        Width = 167
        Height = 21
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Scanner update mode:'
      end
      object cbScannerMode: TComboBox
        Left = 177
        Top = 5
        Width = 138
        Height = 21
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
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
        Left = 5
        Top = 39
        Width = 192
        Height = 26
        Hint = 
          'Hide hook at import/delayed_import to apphelp.dll and kernelbase' +
          '.dll'
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Use Scanner Filter'
        ParentShowHint = False
        ShowHint = True
        TabOrder = 1
      end
    end
    object TabSheet4: TTabSheet
      Margins.Left = 5
      Margins.Top = 5
      Margins.Right = 5
      Margins.Bottom = 5
      Caption = 'TabSheet4'
      ImageIndex = 3
      object cbShowColors: TCheckBox
        Left = 5
        Top = 5
        Width = 277
        Height = 25
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Show colors'
        TabOrder = 0
      end
      object GroupBox1: TGroupBox
        Left = 5
        Top = 39
        Width = 433
        Height = 374
        Margins.Left = 5
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Caption = 'Color scheme:'
        TabOrder = 1
        object Label1: TLabel
          Left = 53
          Top = 36
          Width = 94
          Height = 21
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Alignment = taRightJustify
          Caption = 'Image color:'
        end
        object Label2: TLabel
          Left = 49
          Top = 120
          Width = 98
          Height = 21
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Alignment = taRightJustify
          Caption = 'Private color:'
        end
        object Label3: TLabel
          Left = 27
          Top = 162
          Width = 120
          Height = 21
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Alignment = taRightJustify
          Caption = 'Shareable color:'
        end
        object Label4: TLabel
          Left = 15
          Top = 204
          Width = 132
          Height = 21
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Alignment = taRightJustify
          Caption = 'Mapped file color:'
        end
        object Label5: TLabel
          Left = 62
          Top = 246
          Width = 85
          Height = 21
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Alignment = taRightJustify
          Caption = 'Heap color:'
        end
        object Label6: TLabel
          Left = 10
          Top = 288
          Width = 137
          Height = 21
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Alignment = taRightJustify
          Caption = 'Thread data color:'
        end
        object Label7: TLabel
          Left = 46
          Top = 330
          Width = 101
          Height = 21
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Alignment = taRightJustify
          Caption = 'System color:'
        end
        object Label8: TLabel
          Left = 18
          Top = 78
          Width = 129
          Height = 21
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Alignment = taRightJustify
          Caption = 'Image part color:'
        end
        object pnImage0: TPanel
          Left = 156
          Top = 32
          Width = 254
          Height = 33
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Color = clMedGray
          ParentBackground = False
          TabOrder = 0
          OnClick = pnImage0Click
        end
        object pnImage1: TPanel
          Tag = 1
          Left = 156
          Top = 74
          Width = 254
          Height = 33
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Color = clMedGray
          ParentBackground = False
          TabOrder = 1
          OnClick = pnImage0Click
        end
        object pnImage2: TPanel
          Tag = 2
          Left = 156
          Top = 116
          Width = 254
          Height = 33
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Color = clMedGray
          ParentBackground = False
          TabOrder = 2
          OnClick = pnImage0Click
        end
        object pnImage3: TPanel
          Tag = 3
          Left = 156
          Top = 158
          Width = 254
          Height = 33
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Color = clMedGray
          ParentBackground = False
          TabOrder = 3
          OnClick = pnImage0Click
        end
        object pnImage4: TPanel
          Tag = 4
          Left = 156
          Top = 200
          Width = 254
          Height = 33
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Color = clMedGray
          ParentBackground = False
          TabOrder = 4
          OnClick = pnImage0Click
        end
        object pnImage5: TPanel
          Tag = 5
          Left = 156
          Top = 242
          Width = 254
          Height = 33
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Color = clMedGray
          ParentBackground = False
          TabOrder = 5
          OnClick = pnImage0Click
        end
        object pnImage6: TPanel
          Tag = 6
          Left = 156
          Top = 284
          Width = 254
          Height = 33
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
          Color = clMedGray
          ParentBackground = False
          TabOrder = 6
          OnClick = pnImage0Click
        end
        object pnImage7: TPanel
          Tag = 7
          Left = 156
          Top = 326
          Width = 254
          Height = 33
          Margins.Left = 5
          Margins.Top = 5
          Margins.Right = 5
          Margins.Bottom = 5
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
