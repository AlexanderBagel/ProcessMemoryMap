object dlgRegionProps: TdlgRegionProps
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - Region Properties'
  ClientHeight = 548
  ClientWidth = 958
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  KeyPreview = True
  OldCreateOrder = False
  Position = poMainFormCenter
  OnActivate = FormActivate
  OnClose = FormClose
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  OnDeactivate = FormDeactivate
  OnKeyPress = FormKeyPress
  PixelsPerInch = 96
  TextHeight = 13
  object edProperties: TRichEdit
    Left = 0
    Top = 0
    Width = 958
    Height = 548
    Align = alClient
    Font.Charset = RUSSIAN_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    HideSelection = False
    ParentFont = False
    PopupMenu = mnuPopup
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 0
    Zoom = 100
    OnMouseDown = edPropertiesMouseDown
    OnMouseUp = edPropertiesMouseUp
  end
  object mnuPopup: TPopupMenu
    OnPopup = mnuPopupPopup
    Left = 376
    Top = 248
    object mnuGotoAddress: TMenuItem
      Caption = 'Go to Address...'
      Default = True
      ShortCut = 13
      OnClick = mnuGotoAddressClick
    end
    object N3: TMenuItem
      Caption = '-'
    end
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
    object N1: TMenuItem
      Caption = '-'
    end
    object mnuRefresh: TMenuItem
      Caption = 'Refresh'
      ShortCut = 116
      OnClick = mnuRefreshClick
    end
    object N2: TMenuItem
      Caption = '-'
    end
    object mnuTopMostWnd: TMenuItem
      Caption = 'TopMost Window'
      ShortCut = 16468
      OnClick = mnuTopMostWndClick
    end
    object mnuShowAsDisassembly: TMenuItem
      AutoCheck = True
      Caption = 'Show as disassembly'
      ShortCut = 16452
      OnClick = mnuShowAsDisassemblyClick
    end
    object mnuDasmMode: TMenuItem
      Caption = 'Change disasm mode'
      object mnuDasmModeAuto: TMenuItem
        Caption = 'Auto detect'
        Checked = True
        GroupIndex = 1
        RadioItem = True
        OnClick = mnuDasmModeAutoClick
      end
      object mnuDasmMode86: TMenuItem
        Tag = 1
        Caption = 'x86'
        GroupIndex = 1
        RadioItem = True
        ShortCut = 16440
        OnClick = mnuDasmModeAutoClick
      end
      object mnuDasmMode64: TMenuItem
        Tag = 2
        Caption = 'x64'
        GroupIndex = 1
        RadioItem = True
        ShortCut = 16438
        OnClick = mnuDasmModeAutoClick
      end
    end
  end
  object tmrAutoRefresh: TTimer
    Enabled = False
    OnTimer = tmrAutoRefreshTimer
    Left = 472
    Top = 280
  end
end
