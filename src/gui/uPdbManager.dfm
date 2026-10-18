inherited dlgPdbManager: TdlgPdbManager
  Caption = 'Process Memory Map - PDB Manager'
  ClientHeight = 763
  ClientWidth = 1584
  StyleElements = [seFont, seClient, seBorder]
  OnAfterMonitorDpiChanged = FormAfterMonitorDpiChanged
  OnClose = FormClose
  OnCloseQuery = FormCloseQuery
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  ExplicitWidth = 1606
  ExplicitHeight = 819
  PixelsPerInch = 144
  TextHeight = 23
  object vstPdbData: TVirtualStringTree
    Left = 0
    Top = 0
    Width = 1584
    Height = 735
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Align = alClient
    DefaultNodeHeight = 27
    Header.AutoSizeIndex = 0
    Header.Height = 27
    Header.MaxHeight = 15000
    Header.MinHeight = 15
    Header.Options = [hoAutoResize, hoColumnResize, hoShowImages, hoShowSortGlyphs, hoVisible, hoHeaderClickAutoSort]
    HintMode = hmTooltip
    Indent = 27
    Margin = 6
    ParentShowHint = False
    PopupMenu = pmPdb
    ShowHint = True
    TabOrder = 0
    TextMargin = 6
    TreeOptions.MiscOptions = [toAcceptOLEDrop, toCheckSupport, toFullRepaintOnResize, toInitOnSave, toToggleOnDblClick, toWheelPanning, toEditOnClick]
    TreeOptions.PaintOptions = [toHideFocusRect, toShowButtons, toShowDropmark, toShowRoot, toShowVertGridLines, toThemeAware, toUseBlendedImages, toFullVertGridLines, toUseBlendedSelection, toUseExplorerTheme]
    TreeOptions.SelectionOptions = [toFullRowSelect, toMultiSelect]
    OnAddToSelection = vstPdbDataAddToSelection
    OnAfterCellPaint = vstPdbDataAfterCellPaint
    OnBeforeCellPaint = vstPdbDataBeforeCellPaint
    OnGetText = vstPdbDataGetText
    OnGetHint = vstPdbDataGetHint
    OnHeaderClick = vstPdbDataHeaderClick
    Touch.InteractiveGestures = [igPan, igPressAndTap]
    Touch.InteractiveGestureOptions = [igoPanSingleFingerHorizontal, igoPanSingleFingerVertical, igoPanInertia, igoPanGutter, igoParentPassthrough]
    Columns = <
      item
        Position = 0
        Text = 'Binary'
        Width = 670
      end
      item
        Position = 1
        Text = 'Debug'
        Width = 300
      end
      item
        Position = 2
        Text = 'State'
        Width = 200
      end
      item
        Position = 3
        Text = 'Size'
        Width = 210
      end
      item
        Position = 4
        Text = 'SymCount'
        Width = 200
      end>
  end
  object StatusBar: TStatusBar
    Left = 0
    Top = 735
    Width = 1584
    Height = 28
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Panels = <
      item
        Width = 300
      end
      item
        Width = 300
      end
      item
        Width = 50
      end>
  end
  object pmPdb: TPopupMenu
    OnPopup = pmPdbPopup
    Left = 636
    Top = 324
    object mnuFlag: TMenuItem
      Caption = 'Filter'
      object mnuFlagCurrentProcess: TMenuItem
        Tag = 4
        Caption = 'Current Process'
        OnClick = mnuFlagCurrentProcessClick
      end
      object mnuFlagActual: TMenuItem
        Tag = 1
        Caption = 'Actual'
        OnClick = mnuFlagCurrentProcessClick
      end
      object mnuFlagOldest: TMenuItem
        Tag = 2
        Caption = 'Oldest'
        OnClick = mnuFlagCurrentProcessClick
      end
      object mnuFlagBroken: TMenuItem
        Tag = 3
        Caption = 'Broken'
        OnClick = mnuFlagCurrentProcessClick
      end
      object mnuFlagUnknown: TMenuItem
        Caption = 'Unknown'
        OnClick = mnuFlagCurrentProcessClick
      end
      object mnuFlagAll: TMenuItem
        Tag = 5
        Caption = 'All'
        OnClick = mnuFlagCurrentProcessClick
      end
    end
    object All2: TMenuItem
      Caption = '-'
    end
    object mnuDownloadSel: TMenuItem
      Caption = 'Download Selected'
      OnClick = mnuDownloadSelClick
    end
    object mnuDownloadAll: TMenuItem
      Caption = 'Download All Available'
      OnClick = mnuDownloadAllClick
    end
    object mnuPause: TMenuItem
      Caption = 'Pause'
      OnClick = mnuPauseClick
    end
    object mnuResume: TMenuItem
      Caption = 'Resume'
      OnClick = mnuResumeClick
    end
    object mnuStop: TMenuItem
      Caption = 'Stop'
      OnClick = mnuStopClick
    end
    object mnuDeleteSel: TMenuItem
      Caption = 'Delete Selected'
      OnClick = mnuDeleteSelClick
    end
    object mnuDeleteAll: TMenuItem
      Caption = 'Delete All'
      OnClick = mnuDeleteAllClick
    end
    object N2: TMenuItem
      Caption = '-'
    end
    object mnuLock: TMenuItem
      Caption = 'Lock Selected'
      OnClick = mnuLockClick
    end
    object mnuUnlock: TMenuItem
      Caption = 'Unlock Selected'
      OnClick = mnuUnlockClick
    end
    object N1: TMenuItem
      Caption = '-'
    end
    object mnuOpenPDB: TMenuItem
      Caption = 'Open PDB In Explorer...'
      OnClick = mnuOpenPDBClick
    end
    object mnuOpenBinary: TMenuItem
      Caption = 'Open Binary in Explorer...'
      OnClick = mnuOpenBinaryClick
    end
  end
end
