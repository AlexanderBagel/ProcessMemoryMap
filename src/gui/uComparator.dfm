object dlgComparator: TdlgComparator
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - Compare Result'
  ClientHeight = 528
  ClientWidth = 786
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
  object Panel1: TPanel
    Left = 0
    Top = 487
    Width = 786
    Height = 41
    Align = alBottom
    BevelOuter = bvNone
    TabOrder = 0
    DesignSize = (
      786
      41)
    object Button1: TButton
      Left = 704
      Top = 6
      Width = 75
      Height = 25
      Anchors = [akTop, akRight]
      Cancel = True
      Caption = 'Cancel'
      ModalResult = 2
      TabOrder = 0
    end
    object btnSave: TButton
      Left = 623
      Top = 6
      Width = 75
      Height = 25
      Anchors = [akTop, akRight]
      Caption = 'Save'
      Default = True
      TabOrder = 1
      OnClick = btnSaveClick
    end
  end
  object edChanges: TRichEdit
    Left = 0
    Top = 0
    Width = 786
    Height = 487
    Align = alClient
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = []
    Lines.Strings = (
      'edChanges')
    ParentFont = False
    PopupMenu = PopupMenu
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 1
    Zoom = 100
  end
  object SaveDialog: TSaveDialog
    DefaultExt = 'rtf'
    Filter = 'Report (*.rtf)|*.rtf|All files (*.*)|*.*'
    Left = 24
    Top = 32
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
end
