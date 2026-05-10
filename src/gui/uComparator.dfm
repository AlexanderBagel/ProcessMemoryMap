object dlgComparator: TdlgComparator
  Left = 0
  Top = 0
  Margins.Left = 5
  Margins.Top = 5
  Margins.Right = 5
  Margins.Bottom = 5
  Caption = 'Process Memory Map - Compare Result'
  ClientHeight = 792
  ClientWidth = 1188
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -17
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poMainFormCenter
  PixelsPerInch = 144
  TextHeight = 21
  object Panel1: TPanel
    Left = 0
    Top = 731
    Width = 1188
    Height = 61
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Align = alBottom
    BevelOuter = bvNone
    TabOrder = 0
    DesignSize = (
      1188
      61)
    object Button1: TButton
      Left = 1056
      Top = 9
      Width = 113
      Height = 38
      Margins.Left = 5
      Margins.Top = 5
      Margins.Right = 5
      Margins.Bottom = 5
      Anchors = [akTop, akRight]
      Cancel = True
      Caption = 'Cancel'
      ModalResult = 2
      TabOrder = 0
    end
    object btnSave: TButton
      Left = 935
      Top = 9
      Width = 112
      Height = 38
      Margins.Left = 5
      Margins.Top = 5
      Margins.Right = 5
      Margins.Bottom = 5
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
    Width = 1188
    Height = 731
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Align = alClient
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -17
    Font.Name = 'Tahoma'
    Font.Style = []
    Lines.Strings = (
      'edChanges')
    ParentFont = False
    PopupMenu = PopupMenu
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 1
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
