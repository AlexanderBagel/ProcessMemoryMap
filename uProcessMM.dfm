object dlgProcessMM: TdlgProcessMM
  Left = 0
  Top = 0
  Caption = 'Process Memory Map'
  ClientHeight = 589
  ClientWidth = 1007
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  KeyPreview = True
  Menu = MainMenu
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  OnKeyPress = FormKeyPress
  OnShow = FormShow
  DesignSize = (
    1007
    589)
  PixelsPerInch = 96
  TextHeight = 13
  object imgProcess: TImage
    Left = 8
    Top = 8
    Width = 32
    Height = 32
  end
  object lblProcessName: TLabel
    Left = 56
    Top = 8
    Width = 41
    Height = 13
    Caption = 'Process:'
  end
  object lblProcessNameData: TLabel
    Left = 103
    Top = 8
    Width = 3
    Height = 13
  end
  object lblProcessPID: TLabel
    Left = 56
    Top = 24
    Width = 21
    Height = 13
    Caption = 'PID:'
  end
  object lblProcessPIDData: TLabel
    Left = 103
    Top = 24
    Width = 3
    Height = 13
  end
  object gbSummary: TGroupBox
    Left = 8
    Top = 43
    Width = 991
    Height = 215
    Anchors = [akLeft, akTop, akRight]
    Caption = 'Summary:'
    TabOrder = 0
    object lvSummary: TVirtualStringTree
      Left = 2
      Top = 15
      Width = 987
      Height = 198
      Align = alClient
      Header.AutoSizeIndex = 0
      Header.Font.Charset = DEFAULT_CHARSET
      Header.Font.Color = clWindowText
      Header.Font.Height = -11
      Header.Font.Name = 'Tahoma'
      Header.Font.Style = []
      Header.Height = 24
      Header.Options = [hoColumnResize, hoDrag, hoShowSortGlyphs, hoVisible]
      TabOrder = 0
      TreeOptions.PaintOptions = [toShowButtons, toShowDropmark, toThemeAware, toUseBlendedImages, toUseBlendedSelection]
      TreeOptions.SelectionOptions = [toFullRowSelect]
      OnBeforeItemErase = lvSummaryBeforeItemErase
      OnGetText = lvSummaryGetText
      OnNodeClick = lvSummaryNodeClick
      Columns = <
        item
          Position = 0
          Width = 100
          WideText = 'Type'
        end
        item
          Alignment = taRightJustify
          Position = 1
          Width = 150
          WideText = 'Size'
        end
        item
          Alignment = taRightJustify
          Position = 2
          Width = 150
          WideText = 'Commited'
        end
        item
          Alignment = taRightJustify
          Position = 3
          Width = 150
          WideText = 'Blocks'
        end>
    end
  end
  object stMemoryMap: TVirtualStringTree
    Left = 8
    Top = 264
    Width = 989
    Height = 315
    Anchors = [akLeft, akTop, akRight, akBottom]
    Header.AutoSizeIndex = 0
    Header.Font.Charset = DEFAULT_CHARSET
    Header.Font.Color = clWindowText
    Header.Font.Height = -11
    Header.Font.Name = 'Tahoma'
    Header.Font.Style = []
    Header.Height = 24
    Header.Options = [hoColumnResize, hoDrag, hoShowSortGlyphs, hoVisible]
    PopupMenu = PopupMenu
    TabOrder = 1
    TreeOptions.PaintOptions = [toShowButtons, toShowDropmark, toShowRoot, toShowTreeLines, toShowVertGridLines, toThemeAware, toUseBlendedImages, toUseBlendedSelection, toUseExplorerTheme, toHideTreeLinesIfThemed]
    TreeOptions.SelectionOptions = [toFullRowSelect, toRightClickSelect]
    OnBeforeItemErase = stMemoryMapBeforeItemErase
    OnGetText = stMemoryMapGetText
    OnNodeDblClick = stMemoryMapNodeDblClick
    Columns = <
      item
        Position = 0
        Width = 170
        WideText = 'Address'
      end
      item
        Position = 1
        Width = 300
        WideText = 'Type'
      end
      item
        Alignment = taRightJustify
        CaptionAlignment = taRightJustify
        Options = [coAllowClick, coDraggable, coEnabled, coParentBidiMode, coParentColor, coResizable, coShowDropMark, coVisible, coAllowFocus, coUseCaptionAlignment]
        Position = 2
        Width = 75
        WideText = 'Size'
      end
      item
        Position = 3
        Width = 64
        WideText = 'Section'
      end
      item
        Position = 4
        Width = 120
        WideText = 'Contains'
      end
      item
        Position = 5
        Width = 100
        WideText = 'Access'
      end
      item
        Position = 6
        Width = 100
        WideText = 'Initial Access'
      end
      item
        Alignment = taRightJustify
        CaptionAlignment = taRightJustify
        Options = [coAllowClick, coDraggable, coEnabled, coParentBidiMode, coParentColor, coResizable, coShowDropMark, coVisible, coAllowFocus, coUseCaptionAlignment]
        Position = 7
        WideText = 'Blocks'
      end
      item
        Position = 8
        Width = 560
        WideText = 'Details'
      end>
  end
  object MainMenu: TMainMenu
    Images = MainMenuImageList
    Left = 448
    Top = 8
    object mnuFile: TMenuItem
      Caption = 'File'
      object mnuSelectProcess: TMenuItem
        Action = acSelectProcess
      end
      object N1: TMenuItem
        Caption = '-'
      end
      object mnuOpen: TMenuItem
        Action = acOpen
      end
      object mnuCompare: TMenuItem
        Action = acCompare
      end
      object mnuSave: TMenuItem
        Action = acSave
      end
      object N2: TMenuItem
        Caption = '-'
      end
      object mnuRunAsAdmin: TMenuItem
        Action = acRunAsAdmin
      end
      object N3: TMenuItem
        Caption = '-'
      end
      object mnuExit: TMenuItem
        Action = acExit
      end
    end
    object mnuEdit: TMenuItem
      Caption = 'Edit'
      object mnuRefresh: TMenuItem
        Action = acRefresh
      end
      object N7: TMenuItem
        Caption = '-'
      end
      object mnuCopyAddress: TMenuItem
        Action = acCopyAddress
      end
      object mnuCopySelected: TMenuItem
        Action = acCopySelected
      end
      object N4: TMenuItem
        Caption = '-'
      end
      object mnuProprety: TMenuItem
        Action = acRegionProps
      end
    end
    object mnuSearch: TMenuItem
      Caption = 'Search'
      object mnuShowAddr: TMenuItem
        Action = acSearchAddress
      end
      object mnuFind: TMenuItem
        Action = acSearchData
      end
    end
    object mnuUtils: TMenuItem
      Caption = 'Utils'
      object mnuQuery: TMenuItem
        Action = acQueryAddr
      end
      object mnuShowExport: TMenuItem
        Action = acShowExports
      end
      object N11: TMenuItem
        Caption = '-'
      end
      object DumpAddress1: TMenuItem
        Action = acDumpAddr
      end
      object DumpRegion2: TMenuItem
        Action = acDumpRegion
      end
    end
    object mnuOptions: TMenuItem
      Caption = 'Options'
      object mnuExpand: TMenuItem
        Action = acExpandAll
      end
      object mnuCollapse: TMenuItem
        Action = acCollapseAll
      end
      object N5: TMenuItem
        Caption = '-'
      end
      object mnuSettings: TMenuItem
        Action = acSettings
      end
    end
    object mnuHelp: TMenuItem
      Caption = 'Help'
      object mnuAbout: TMenuItem
        Action = acAbout
      end
    end
  end
  object MainMenuImageList: TImageList
    ColorDepth = cd32Bit
    Left = 528
    Top = 8
  end
  object SavePMMDialog: TSaveDialog
    DefaultExt = 'pmm'
    Filter = 'Process Memory Map File (*.pmm)|*.pmm|All Files (*.*)|*.*'
    Options = [ofOverwritePrompt, ofHideReadOnly, ofPathMustExist, ofEnableSizing]
    Left = 376
    Top = 8
  end
  object OpenPMMDialog: TOpenDialog
    DefaultExt = 'pmm'
    Filter = 'Process Memory Map File (*.pmm)|*.pmm|All Files (*.*)|*.*'
    Left = 288
    Top = 8
  end
  object PopupMenu: TPopupMenu
    Left = 200
    Top = 8
    object CopyAddress1: TMenuItem
      Action = acCopyAddress
    end
    object CopySelected1: TMenuItem
      Action = acCopySelected
    end
    object N8: TMenuItem
      Caption = '-'
    end
    object Queryaddress2: TMenuItem
      Action = acQueryAddr
    end
    object Find1: TMenuItem
      Action = acSearchData
    end
    object N10: TMenuItem
      Caption = '-'
    end
    object DumpRegion1: TMenuItem
      Action = acDumpRegion
    end
    object N9: TMenuItem
      Caption = '-'
    end
    object ExpandAll1: TMenuItem
      Action = acExpandAll
    end
    object CollapseAll1: TMenuItem
      Action = acCollapseAll
    end
    object N6: TMenuItem
      Caption = '-'
    end
    object Regionproperties1: TMenuItem
      Action = acRegionProps
      Default = True
    end
  end
  object ActionManager: TActionManager
    Left = 120
    Top = 8
    StyleName = 'Platform Default'
    object acSelectProcess: TAction
      Category = 'File'
      Caption = 'Select Process...'
      ShortCut = 16464
      OnExecute = acSelectProcessExecute
    end
    object acOpen: TAction
      Category = 'File'
      Caption = 'Open...'
      ShortCut = 16463
      OnExecute = acOpenExecute
    end
    object acCompare: TAction
      Category = 'File'
      Caption = 'Compare with...'
      OnExecute = acCompareExecute
      OnUpdate = acCompareUpdate
    end
    object acSave: TAction
      Category = 'File'
      Caption = 'Save...'
      ShortCut = 16467
      OnExecute = acSaveExecute
      OnUpdate = acSaveUpdate
    end
    object acRunAsAdmin: TAction
      Category = 'File'
      Caption = 'Run as administrator'
      OnExecute = acRunAsAdminExecute
    end
    object acExit: TAction
      Category = 'File'
      Caption = 'Exit'
      OnExecute = acExitExecute
    end
    object acRefresh: TAction
      Category = 'Edit'
      Caption = 'Refresh'
      ShortCut = 116
      OnExecute = acRefreshExecute
      OnUpdate = acSaveUpdate
    end
    object acCopyAddress: TAction
      Category = 'Edit'
      Caption = 'Copy Address'
      ShortCut = 16451
      OnExecute = acCopyAddressExecute
      OnUpdate = acDumpRegionUpdate
    end
    object acCopySelected: TAction
      Category = 'Edit'
      Caption = 'Copy Selected'
      OnExecute = acCopySelectedExecute
      OnUpdate = acDumpRegionUpdate
    end
    object acRegionProps: TAction
      Category = 'Edit'
      Caption = 'Region Properties...'
      OnExecute = acRegionPropsExecute
      OnUpdate = acDumpRegionUpdate
    end
    object acSearchAddress: TAction
      Category = 'Search'
      Caption = 'Search Address...'
      ShortCut = 16449
      OnExecute = acSearchAddressExecute
      OnUpdate = acCompareUpdate
    end
    object acQueryAddr: TAction
      Category = 'Utils'
      Caption = 'Query Address'
      ShortCut = 16465
      OnExecute = acQueryAddrExecute
      OnUpdate = acSaveUpdate
    end
    object acSearchData: TAction
      Category = 'Search'
      Caption = 'Search Data...'
      ShortCut = 16454
      OnExecute = acSearchDataExecute
      OnUpdate = acSaveUpdate
    end
    object acShowExports: TAction
      Category = 'Utils'
      Caption = 'Show Export List...'
      ShortCut = 16453
      OnExecute = acShowExportsExecute
      OnUpdate = acSaveUpdate
    end
    object acDumpAddr: TAction
      Category = 'Utils'
      Caption = 'Dump Address...'
      OnExecute = acDumpAddrExecute
      OnUpdate = acSaveUpdate
    end
    object acDumpRegion: TAction
      Category = 'Utils'
      Caption = 'Dump Selected Region'
      OnExecute = acDumpRegionExecute
      OnUpdate = acDumpRegionUpdate
    end
    object acExpandAll: TAction
      Category = 'Option'
      Caption = 'Expand All'
      OnExecute = acExpandAllExecute
    end
    object acCollapseAll: TAction
      Category = 'Option'
      Caption = 'Collapse All'
      OnExecute = acCollapseAllExecute
    end
    object acSettings: TAction
      Category = 'Option'
      Caption = 'Settings...'
      OnExecute = acSettingsExecute
    end
    object acAbout: TAction
      Category = 'Help'
      Caption = 'About'
      OnExecute = acAboutExecute
    end
  end
  object SaveDMPDialog: TSaveDialog
    DefaultExt = 'dmp'
    Filter = 'Memory Dump File (*.dmp)|*.dmp|All Files (*.*)|*.*'
    Options = [ofOverwritePrompt, ofHideReadOnly, ofPathMustExist, ofEnableSizing]
    Left = 616
    Top = 8
  end
end
