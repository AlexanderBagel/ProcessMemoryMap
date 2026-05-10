object dlgResources: TdlgResources
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - Resources'
  ClientHeight = 443
  ClientWidth = 837
  Color = clBtnFace
  KeyPreview = True
  Position = poMainFormCenter
  OnClose = FormClose
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  OnKeyPress = FormKeyPress
  OnShow = FormShow
  object spLeftSplitter: TSplitter
    Left = 241
    Top = 35
    Width = 2
    Height = 408
  end
  object tvResources: TVirtualStringTree
    Left = 0
    Top = 35
    Width = 241
    Height = 408
    Align = alLeft
    DefaultNodeHeight = 17
    Header.AutoSizeIndex = 0
    Header.Height = 15
    Header.MainColumn = -1
    TabOrder = 0
    TreeOptions.PaintOptions = [toHotTrack, toShowButtons, toShowDropmark, toShowRoot, toShowTreeLines, toThemeAware, toUseBlendedImages, toFullVertGridLines, toUseBlendedSelection, toUseExplorerTheme]
    TreeOptions.SelectionOptions = [toFullRowSelect, toSelectNextNodeOnRemoval]
    OnAddToSelection = tvResourcesAddToSelection
    OnGetText = tvResourcesGetText
    Touch.InteractiveGestures = [igPan, igPressAndTap]
    Touch.InteractiveGestureOptions = [igoPanSingleFingerHorizontal, igoPanSingleFingerVertical, igoPanInertia, igoPanGutter, igoParentPassthrough]
    Columns = <>
  end
  object pnTop: TPanel
    Left = 0
    Top = 0
    Width = 837
    Height = 35
    Align = alTop
    BevelOuter = bvNone
    TabOrder = 1
    object lblFilter: TLabel
      Left = 16
      Top = 9
      Width = 71
      Height = 15
      Caption = 'Filter by type:'
    end
    object cbTypes: TComboBox
      Left = 94
      Top = 6
      Width = 145
      Height = 33
      Style = csDropDownList
      TabOrder = 0
      OnChange = cbTypesChange
    end
  end
  object pnRight: TPanel
    Left = 243
    Top = 35
    Width = 594
    Height = 408
    Align = alClient
    BevelOuter = bvNone
    Caption = 'pnRight'
    TabOrder = 2
    object spBottomSplitter: TSplitter
      Left = 0
      Top = 301
      Width = 594
      Height = 3
      Cursor = crVSplit
      Align = alBottom
    end
    object pcResViewers: TPageControl
      Left = 0
      Top = 0
      Width = 594
      Height = 301
      ActivePage = tsText
      Align = alClient
      TabOrder = 0
      object tsRaw: TTabSheet
        Caption = 'Raw'
        object memResRaw: TMemo
          Left = 0
          Top = 0
          Width = 589
          Height = 274
          Align = alClient
          Font.Charset = RUSSIAN_CHARSET
          Font.Color = clWindowText
          Font.Height = -12
          Font.Name = 'Consolas'
          Font.Style = []
          ParentFont = False
          ReadOnly = True
          ScrollBars = ssBoth
          TabOrder = 0
        end
      end
      object tsText: TTabSheet
        Caption = 'Text'
        ImageIndex = 1
        object memResText: TMemo
          Left = 0
          Top = 0
          Width = 586
          Height = 271
          Align = alClient
          Font.Charset = RUSSIAN_CHARSET
          Font.Color = clWindowText
          Font.Height = -12
          Font.Name = 'Consolas'
          Font.Style = []
          ParentFont = False
          ReadOnly = True
          ScrollBars = ssBoth
          TabOrder = 0
          ExplicitWidth = 589
          ExplicitHeight = 275
        end
      end
      object tsImage: TTabSheet
        Caption = 'Image'
        ImageIndex = 2
        object pbResImage: TPaintBox
          Left = 0
          Top = 0
          Width = 571
          Height = 274
          Align = alClient
          OnPaint = pbResImagePaint
        end
        object ScrollBar1: TScrollBar
          Left = 571
          Top = 0
          Width = 18
          Height = 274
          Align = alRight
          Kind = sbVertical
          PageSize = 0
          TabOrder = 0
          Visible = False
        end
      end
    end
    object memResInfo: TMemo
      Left = 0
      Top = 304
      Width = 594
      Height = 104
      Align = alBottom
      DoubleBuffered = True
      Font.Charset = RUSSIAN_CHARSET
      Font.Color = clWindowText
      Font.Height = -12
      Font.Name = 'Consolas'
      Font.Style = []
      ParentDoubleBuffered = False
      ParentFont = False
      TabOrder = 1
    end
  end
end
