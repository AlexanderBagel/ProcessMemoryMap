object frmShowInitOrder: TfrmShowInitOrder
  Left = 0
  Top = 0
  Caption = 'Show Delphi/Lazarus Unit Init Order'
  ClientHeight = 421
  ClientWidth = 757
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  DesignSize = (
    757
    421)
  PixelsPerInch = 96
  TextHeight = 13
  object lePath: TLabeledEdit
    Left = 8
    Top = 24
    Width = 579
    Height = 21
    Anchors = [akLeft, akTop, akRight]
    EditLabel.Width = 82
    EditLabel.Height = 13
    EditLabel.Caption = 'Executable path:'
    TabOrder = 0
    OnChange = lePathChange
  end
  object btnBrowse: TButton
    Left = 593
    Top = 22
    Width = 75
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Browse...'
    TabOrder = 1
    OnClick = btnBrowseClick
  end
  object btnLoad: TButton
    Left = 674
    Top = 22
    Width = 75
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Load'
    Enabled = False
    TabOrder = 2
    OnClick = btnLoadClick
  end
  object lvReport: TListView
    Left = 8
    Top = 51
    Width = 741
    Height = 307
    Anchors = [akLeft, akTop, akRight, akBottom]
    Columns = <
      item
        Caption = #8470
      end
      item
        AutoSize = True
        Caption = 'UnitName'
      end
      item
        Caption = 'Type'
        Width = 75
      end
      item
        Caption = 'InitVA'
        Width = 100
      end
      item
        Caption = 'FinallyVA'
        Width = 100
      end>
    DoubleBuffered = True
    HideSelection = False
    HotTrack = True
    ReadOnly = True
    RowSelect = True
    ParentDoubleBuffered = False
    PopupMenu = pmCopy
    TabOrder = 3
    ViewStyle = vsReport
    OnCustomDrawItem = lvReportCustomDrawItem
  end
  object memLog: TMemo
    Left = 8
    Top = 364
    Width = 741
    Height = 49
    Anchors = [akLeft, akRight, akBottom]
    ReadOnly = True
    ScrollBars = ssVertical
    TabOrder = 4
  end
  object OpenDialog: TOpenDialog
    DefaultExt = '.exe'
    Filter = 'Executable Files (*.exe)|*.exe|All Files (*.*)|*.*'
    Left = 360
    Top = 232
  end
  object pmCopy: TPopupMenu
    OnPopup = pmCopyPopup
    Left = 440
    Top = 232
    object mnuCopyLine: TMenuItem
      Caption = 'Copy Line'
      OnClick = mnuCopyLineClick
    end
    object mnuCopyUnit: TMenuItem
      Caption = 'Copy Unit Name'
      OnClick = mnuCopyUnitClick
    end
    object mnuCopyInit: TMenuItem
      Tag = 2
      Caption = 'Copy Initialization address'
      OnClick = mnuCopyUnitClick
    end
    object mnuCopyFin: TMenuItem
      Tag = 3
      Caption = 'Copy finalization address'
      OnClick = mnuCopyUnitClick
    end
    object N1: TMenuItem
      Caption = '-'
    end
    object CopyUnitInitializationOrder1: TMenuItem
      Caption = 'Copy Unit Initialization Order'
      OnClick = CopyUnitInitializationOrder1Click
    end
    object CopyAll2: TMenuItem
      Caption = '-'
    end
    object mnuCopyAll: TMenuItem
      Caption = 'Copy All'
      OnClick = mnuCopyAllClick
    end
  end
end
