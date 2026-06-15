object dlgSearchResult: TdlgSearchResult
  Left = 0
  Top = 0
  Margins.Left = 5
  Margins.Top = 5
  Margins.Right = 5
  Margins.Bottom = 5
  Caption = 'Process Memory Map - Search Results'
  ClientHeight = 617
  ClientWidth = 1287
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -17
  Font.Name = 'Tahoma'
  Font.Style = []
  KeyPreview = True
  Position = poScreenCenter
  OnClose = FormClose
  OnKeyPress = FormKeyPress
  PixelsPerInch = 144
  TextHeight = 21
  object PageControl: TPageControl
    Left = 0
    Top = 0
    Width = 1287
    Height = 617
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Align = alClient
    PopupMenu = pmPage
    TabOrder = 0
    OnChange = PageControlChange
  end
  object StatusBar: TStatusBar
    Left = 0
    Top = 392
    Width = 858
    Height = 19
    Panels = <
      item
        Width = 33
      end>
  end
  object pmViewer: TPopupMenu
    Left = 248
    Top = 176
    object mnuOpen: TMenuItem
      Action = acOpen
      Default = True
    end
    object OpenInExplorer1: TMenuItem
      Action = acOpenInExplorer
    end
    object N4: TMenuItem
      Caption = '-'
    end
    object mnuCopyAddress: TMenuItem
      Action = acCopyAddr
    end
    object mnuCopyLine: TMenuItem
      Action = acCopyLine
    end
    object SaveToFile1: TMenuItem
      Action = acSaveToFile
    end
    object N1: TMenuItem
      Caption = '-'
    end
    object mnuClose: TMenuItem
      Action = acClose
    end
    object CloseAllButThis1: TMenuItem
      Caption = 'Close Multiple Pages'
      object CloseAllButThis2: TMenuItem
        Action = acCloseAllButThis
      end
      object CloseAlltotheLeft1: TMenuItem
        Action = acCloseLeft
      end
      object CloseAlltotheRight1: TMenuItem
        Action = acCloseRight
      end
      object N3: TMenuItem
        Caption = '-'
      end
      object mnuCloseAll: TMenuItem
        Action = acCloseAll
      end
    end
  end
  object ActionList1: TActionList
    Left = 472
    Top = 208
    object acOpen: TAction
      Caption = 'Go to Address'
      ShortCut = 13
      OnExecute = acOpenExecute
      OnUpdate = acOpenUpdate
    end
    object acOpenInExplorer: TAction
      Caption = 'Open In Explorer'
      OnExecute = acOpenInExplorerExecute
      OnUpdate = acOpenInExplorerUpdate
    end
    object acCopyAddr: TAction
      Caption = 'Copy Address'
      OnExecute = acCopyAddrExecute
      OnUpdate = acOpenUpdate
    end
    object acCopyLine: TAction
      Caption = 'Copy Line'
      OnExecute = acCopyLineExecute
      OnUpdate = acOpenUpdate
    end
    object acClose: TAction
      Caption = 'Close Page'
      OnExecute = acCloseExecute
    end
    object acCloseAll: TAction
      Caption = 'Close All'
      OnExecute = acCloseAllExecute
    end
    object acCloseLeft: TAction
      Caption = 'Close All to the Left'
      OnExecute = acCloseLeftExecute
      OnUpdate = acCloseLeftUpdate
    end
    object acCloseRight: TAction
      Caption = 'Close All to the Right'
      OnExecute = acCloseRightExecute
      OnUpdate = acCloseRightUpdate
    end
    object acCloseAllButThis: TAction
      Caption = 'Close All But This'
      OnExecute = acCloseAllButThisExecute
      OnUpdate = acCloseAllButThisUpdate
    end
    object acSaveToFile: TAction
      Caption = 'Save To File...'
      OnExecute = acSaveToFileExecute
    end
  end
  object pmPage: TPopupMenu
    Left = 328
    Top = 176
    object MenuItem4: TMenuItem
      Action = acClose
    end
    object MenuItem5: TMenuItem
      Caption = '-'
    end
    object MenuItem6: TMenuItem
      Action = acCloseAllButThis
    end
    object MenuItem7: TMenuItem
      Action = acCloseLeft
    end
    object MenuItem8: TMenuItem
      Action = acCloseRight
    end
    object N2: TMenuItem
      Caption = '-'
    end
    object MenuItem9: TMenuItem
      Action = acCloseAll
    end
  end
  object SaveDialog: TSaveDialog
    DefaultExt = 'txt'
    Filter = 'Text File (*.txt)|*.txt|All Files (*.*)|*.*'
    Options = [ofOverwritePrompt, ofHideReadOnly, ofPathMustExist, ofEnableSizing]
    Left = 588
    Top = 204
  end
end
