object dlgStackConverter: TdlgStackConverter
  Left = 0
  Top = 0
  Caption = 'Sysinternals Process Explorer Call Stack Converter'
  ClientHeight = 588
  ClientWidth = 1225
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object pnTop: TPanel
    Left = 0
    Top = 0
    Width = 1225
    Height = 553
    Align = alClient
    BevelOuter = bvNone
    TabOrder = 0
    object Splitter: TSplitter
      Left = 385
      Top = 0
      Width = 6
      Height = 553
      Color = clBtnShadow
      ParentColor = False
      ExplicitLeft = 431
      ExplicitHeight = 551
    end
    object memStack: TMemo
      Left = 0
      Top = 0
      Width = 385
      Height = 553
      Align = alLeft
      DoubleBuffered = True
      ParentDoubleBuffered = False
      PopupMenu = memPopupMenu
      ScrollBars = ssBoth
      TabOrder = 0
    end
    object lvStack: TListView
      Left = 391
      Top = 0
      Width = 834
      Height = 553
      Align = alClient
      Columns = <
        item
          Caption = 'Address'
          Width = 128
        end
        item
          Caption = 'Module'
          Width = 150
        end
        item
          Caption = 'Unit'
          Width = 135
        end
        item
          Caption = 'Function'
          Width = 330
        end
        item
          Caption = 'Line'
        end>
      DoubleBuffered = True
      RowSelect = True
      ParentDoubleBuffered = False
      ParentShowHint = False
      PopupMenu = lvPopupMenu
      ShowHint = True
      TabOrder = 1
      ViewStyle = vsReport
      OnCustomDrawItem = lvStackCustomDrawItem
      OnInfoTip = lvStackInfoTip
    end
    object pnPaste: TPanel
      Left = 32
      Top = 96
      Width = 297
      Height = 41
      Caption = 'Paste CallStack Here!'
      TabOrder = 2
      object btnPaste: TButton
        Left = 208
        Top = 8
        Width = 75
        Height = 25
        Action = acPaste
        TabOrder = 0
      end
    end
  end
  object pnBottom: TPanel
    Left = 0
    Top = 553
    Width = 1225
    Height = 35
    Align = alBottom
    BevelOuter = bvNone
    TabOrder = 1
    object btnOpen: TButton
      Left = 279
      Top = 6
      Width = 75
      Height = 25
      Caption = 'Open File...'
      TabOrder = 0
      OnClick = btnOpenClick
    end
    object btnConvert: TButton
      Left = 360
      Top = 6
      Width = 97
      Height = 25
      Action = acConvert
      TabOrder = 1
    end
    object edBase: TLabeledEdit
      Left = 152
      Top = 8
      Width = 121
      Height = 21
      EditLabel.Width = 132
      EditLabel.Height = 13
      EditLabel.Caption = 'Image Base Address (HEX):'
      LabelPosition = lpLeft
      TabOrder = 2
      Text = '400000'
      OnChange = edBaseChange
    end
  end
  object OpenDialog: TOpenDialog
    Filter = 
      'Executable file (*.exe)|*.exe|Library (*.dll)|*.dll|All Files (*' +
      '.*)|*.*'
    Left = 448
    Top = 80
  end
  object lvPopupMenu: TPopupMenu
    Left = 520
    Top = 80
    object acCopyAddr1: TMenuItem
      Action = acCopyAddr
    end
    object acCopyLine1: TMenuItem
      Action = acCopyLine
    end
    object N1: TMenuItem
      Caption = '-'
    end
    object acCopyAll1: TMenuItem
      Action = acCopyAll
    end
  end
  object ActionList: TActionList
    Left = 608
    Top = 80
    object acPaste: TAction
      Caption = 'Paste'
      OnExecute = acPasteExecute
      OnUpdate = acPasteUpdate
    end
    object acConvert: TAction
      Caption = 'Convert >>>'
      OnExecute = acConvertExecute
      OnUpdate = acConvertUpdate
    end
    object acCopyAddr: TAction
      Caption = 'acCopyAddr'
      OnExecute = acCopyAddrExecute
      OnUpdate = acCopyAddrUpdate
    end
    object acCopyLine: TAction
      Caption = 'acCopyLine'
      OnExecute = acCopyLineExecute
      OnUpdate = acCopyLineUpdate
    end
    object acCopyAll: TAction
      Caption = 'acCopyAll'
      OnExecute = acCopyAllExecute
      OnUpdate = acCopyAllUpdate
    end
  end
  object memPopupMenu: TPopupMenu
    Left = 520
    Top = 136
    object PasteCollStack1: TMenuItem
      Action = acPaste
    end
  end
end
