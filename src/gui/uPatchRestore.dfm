object dlgPatchRestore: TdlgPatchRestore
  Left = 0
  Top = 0
  Margins.Left = 5
  Margins.Top = 5
  Margins.Right = 5
  Margins.Bottom = 5
  BorderIcons = [biSystemMenu]
  Caption = 'Process Memory Map - Hook Restore'
  ClientHeight = 722
  ClientWidth = 785
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -18
  Font.Name = 'Segoe UI'
  Font.Style = []
  KeyPreview = True
  Position = poScreenCenter
  OnKeyPress = FormKeyPress
  PixelsPerInch = 144  
  DesignSize = (
    785
    722)
  TextHeight = 25
  object Label1: TLabel
    Left = 11
    Top = 11
    Width = 495
    Height = 25
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Caption = 'Select one or more modified memory regions to restore them.'
  end
  object clbPatches: TCheckListBox
    Left = 11
    Top = 45
    Width = 762
    Height = 617
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Anchors = [akLeft, akTop, akRight, akBottom]
    ItemHeight = 26
    TabOrder = 0
    OnClickCheck = clbPatchesClickCheck
  end
  object btnCancel: TButton
    Left = 662
    Top = 671
    Width = 111
    Height = 39
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Anchors = [akRight, akBottom]
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 1
  end
  object btnRestore: TButton
    Left = 539
    Top = 671
    Width = 111
    Height = 39
    Margins.Left = 5
    Margins.Top = 5
    Margins.Right = 5
    Margins.Bottom = 5
    Anchors = [akRight, akBottom]
    Caption = 'Restore'
    Enabled = False
    ModalResult = 1
    TabOrder = 2
  end
end