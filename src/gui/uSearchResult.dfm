object dlgSearchResult: TdlgSearchResult
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - Search Results'
  ClientHeight = 411
  ClientWidth = 852
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  KeyPreview = True
  OldCreateOrder = False
  Position = poScreenCenter
  OnClose = FormClose
  OnKeyPress = FormKeyPress
  PixelsPerInch = 96
  TextHeight = 13
  object PageControl: TPageControl
    Left = 0
    Top = 0
    Width = 852
    Height = 411
    Align = alClient
    PopupMenu = pmPage
    TabOrder = 0
  end
  object pmViewer: TPopupMenu
    Left = 248
    Top = 176
    object mnuOpen: TMenuItem
      Action = acOpen
      Default = True
    end
    object CopyAddress1: TMenuItem
      Action = acCopyAddr
    end
    object N1: TMenuItem
      Caption = '-'
    end
    object Close1: TMenuItem
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
      object CloseAll1: TMenuItem
        Action = acCloseAll
      end
    end
  end
  object ActionList1: TActionList
    Left = 472
    Top = 208
    object acOpen: TAction
      Caption = 'Open'
      OnExecute = acOpenExecute
      OnUpdate = acOpenUpdate
    end
    object acCopyAddr: TAction
      Caption = 'Copy Address'
      OnExecute = acCopyAddrExecute
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
end
