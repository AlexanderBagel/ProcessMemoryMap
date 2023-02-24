object dlgMemoryMapListInfo: TdlgMemoryMapListInfo
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - MemoryMap List Info'
  ClientHeight = 337
  ClientWidth = 635
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
  object edReport: TRichEdit
    Left = 0
    Top = 0
    Width = 635
    Height = 337
    Align = alClient
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    PopupMenu = PopupMenu
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 0
    Zoom = 100
  end
  object PopupMenu: TPopupMenu
    Left = 104
    Top = 32
    object mnuCopy: TMenuItem
      Caption = 'Copy'
      ShortCut = 16451
      OnClick = mnuCopyClick
    end
    object SelectAll1: TMenuItem
      Caption = 'Select All'
      ShortCut = 16449
      OnClick = SelectAll1Click
    end
  end
  object SaveMMLDialog: TSaveDialog
    DefaultExt = 'mml'
    Filter = 'MemoryMap List (*.mml)|*.mml|All Files (*.*)|*.*'
    Options = [ofOverwritePrompt, ofHideReadOnly, ofPathMustExist, ofEnableSizing]
    Left = 192
    Top = 32
  end
end
