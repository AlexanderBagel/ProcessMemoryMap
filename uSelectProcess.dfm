object dlgSelectProcess: TdlgSelectProcess
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - Select Process'
  ClientHeight = 350
  ClientWidth = 481
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
  DesignSize = (
    481
    350)
  PixelsPerInch = 96
  TextHeight = 13
  object lvProcess: TListView
    Left = 0
    Top = 0
    Width = 481
    Height = 311
    Align = alTop
    Anchors = [akLeft, akTop, akRight, akBottom]
    Columns = <
      item
        Caption = 'Name'
        Width = 150
      end
      item
        Alignment = taRightJustify
        Caption = 'PID'
        Width = 75
      end
      item
        AutoSize = True
        Caption = 'User'
      end>
    Groups = <
      item
        Header = 'Newest Processes'
        GroupID = 0
        State = [lgsNormal]
        HeaderAlign = taLeftJustify
        FooterAlign = taLeftJustify
        TitleImage = -1
      end
      item
        Header = 'Other processes'
        GroupID = 1
        State = [lgsNormal]
        HeaderAlign = taLeftJustify
        FooterAlign = taLeftJustify
        TitleImage = -1
      end>
    ReadOnly = True
    RowSelect = True
    SmallImages = il16
    TabOrder = 0
    ViewStyle = vsReport
    OnColumnClick = lvProcessColumnClick
    OnDblClick = lvProcessDblClick
    OnMouseUp = lvProcessMouseUp
    OnSelectItem = lvProcessSelectItem
  end
  object btnRefresh: TButton
    Left = 8
    Top = 318
    Width = 75
    Height = 25
    Anchors = [akLeft, akBottom]
    Caption = 'Refresh'
    TabOrder = 1
    OnClick = btnRefreshClick
  end
  object btnShowAll: TButton
    Left = 96
    Top = 318
    Width = 129
    Height = 25
    Anchors = [akLeft, akBottom]
    Caption = 'Show all processes'
    ElevationRequired = True
    TabOrder = 2
    OnClick = btnShowAllClick
  end
  object btnCancel: TButton
    Left = 398
    Top = 317
    Width = 75
    Height = 25
    Anchors = [akRight, akBottom]
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 3
  end
  object btnDefault: TButton
    Left = 317
    Top = 317
    Width = 75
    Height = 25
    Anchors = [akRight, akBottom]
    Caption = 'OK'
    Default = True
    TabOrder = 4
    OnClick = btnDefaultClick
  end
  object il16: TImageList
    ColorDepth = cd32Bit
    Left = 16
    Top = 32
  end
end
