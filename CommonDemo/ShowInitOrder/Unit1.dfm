object frmShowInitOrder: TfrmShowInitOrder
  Left = 0
  Top = 0
  Margins.Left = 5
  Margins.Top = 5
  Margins.Right = 5
  Margins.Bottom = 5
  Caption = 'Show Delphi/Lazarus Unit Init Order'
  ClientHeight = 632
  ClientWidth = 1136
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -17
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  PixelsPerInch = 144
  DesignSize = (
    1136
    632)
  TextHeight = 21
  object lePath: TLabeledEdit
    Left = 12
    Top = 36
    Width = 869
    Height = 29
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Anchors = [akLeft, akTop, akRight]
    EditLabel.Width = 125
    EditLabel.Height = 21
    EditLabel.Margins.Left = 5
    EditLabel.Margins.Top = 5
    EditLabel.Margins.Right = 5
    EditLabel.Margins.Bottom = 5
    EditLabel.Caption = 'Executable path:'
    TabOrder = 0
    Text = ''
    OnChange = lePathChange
  end
  object btnBrowse: TButton
    Left = 890
    Top = 33
    Width = 112
    Height = 38
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Anchors = [akTop, akRight]
    Caption = 'Browse...'
    TabOrder = 1
    OnClick = btnBrowseClick
  end
  object btnLoad: TButton
    Left = 1011
    Top = 33
    Width = 113
    Height = 38
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Anchors = [akTop, akRight]
    Caption = 'Load'
    Enabled = False
    TabOrder = 2
    OnClick = btnLoadClick
  end
  object lvReport: TListView
    Left = 12
    Top = 77
    Width = 1112
    Height = 460
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Anchors = [akLeft, akTop, akRight, akBottom]
    Columns = <
      item
        Caption = #8470
        Width = 75
      end
      item
        AutoSize = True
        Caption = 'UnitName'
      end
      item
        Caption = 'Type'
        Width = 113
      end
      item
        Caption = 'InitVA'
        Width = 150
      end
      item
        Caption = 'FinallyVA'
        Width = 150
      end>
    DoubleBuffered = True
    HideSelection = False
    HotTrack = True
    Items.ItemData = {050000000000000000}
    ReadOnly = True
    RowSelect = True
    ParentDoubleBuffered = False
    PopupMenu = pmCopy
    TabOrder = 3
    ViewStyle = vsReport
    OnCustomDrawItem = lvReportCustomDrawItem
  end
  object memLog: TMemo
    Left = 12
    Top = 546
    Width = 1112
    Height = 74
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
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
