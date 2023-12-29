object dlgKnownData: TdlgKnownData
  Left = 0
  Top = 0
  Caption = 'Process Memory Map - Known Data'
  ClientHeight = 544
  ClientWidth = 527
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  KeyPreview = True
  OldCreateOrder = False
  Position = poMainFormCenter
  OnClose = FormClose
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  OnKeyPress = FormKeyPress
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 13
  object tvData: TVirtualStringTree
    Left = 0
    Top = 0
    Width = 527
    Height = 544
    Align = alClient
    Header.AutoSizeIndex = 0
    Header.Height = 13
    Header.MainColumn = -1
    Images = il16
    PopupMenu = pmCopy
    TabOrder = 0
    TreeOptions.PaintOptions = [toShowButtons, toShowDropmark, toShowRoot, toShowTreeLines, toThemeAware, toUseBlendedImages, toFullVertGridLines, toUseExplorerTheme]
    OnDblClick = tvDataDblClick
    OnGetText = tvDataGetText
    OnGetImageIndex = tvDataGetImageIndex
    Touch.InteractiveGestures = [igPan, igPressAndTap]
    Touch.InteractiveGestureOptions = [igoPanSingleFingerHorizontal, igoPanSingleFingerVertical, igoPanInertia, igoPanGutter, igoParentPassthrough]
    Columns = <>
  end
  object il16: TImageList
    Left = 32
    Top = 16
    Bitmap = {
      494C01010A001800040010001000FFFFFFFFFF10FFFFFFFFFFFFFFFF424D3600
      0000000000003600000028000000400000003000000001002000000000000030
      00000000000000000000000000000000000000000000AF773F00AF773F00AF77
      3F00AF773F00AF773F00AF773F00AF773F00AF773F00AF773F00AF773F000000
      00000000000000000000000000000000000000000000AF773F00AF773F00AF77
      3F00AF773F00AF773F00AF773F00AF773F00AF773F00AF773F00AF773F000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000AF773F00FFF0F000FFF0F000FFF0
      F000FFF0F000FFF0F000FFF0F000FFF0F000FFF0F000FFF0F000AF773F000000
      000000000000000000000000000000000000AF773F00FFF0F000FFF0F000FFF0
      F000FFF0F000FFF0F000FFF0F000FFF0F000FFF0F000FFF0F000AF773F000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000AF773F00FFF0F0005F3F1F005F3F
      1F00AF773F00FFF0F0005F3F1F005F3F1F005F3F1F00FFF0F000AF773F000000
      000000000000000000000000000000000000AF773F00FFF0F000AF773F005F3F
      1F00AF773F00FFF0F000FFF0F000FFF0F0005F3F1F00FFF0F000AF773F000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000AF773F00FFF0F000FFF0F000FFF0
      F0005F3F1F00FFF0F0005F3F1F00FFF0F000FFF0F000FFF0F000AF773F000000
      000000000000000000000000000000000000AF773F00FFF0F0005F3F1F00FFF0
      F0005F3F1F00FFF0F000FFF0F000FFF0F0005F3F1F00FFF0F000AF773F000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000AF773F00FFF0F0005F3F1F005F3F
      1F005F3F1F00FFF0F000FFF0F0005F3F1F00FFF0F000FFF0F000AF773F000000
      000000000000000000000000000000000000AF773F00FFF0F0005F3F1F005F3F
      1F00AF773F00FFF0F000AF773F005F3F1F005F3F1F00FFF0F000AF773F000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000AF773F00FFF0F000FFF0F000FFF0
      F0005F3F1F00FFF0F000FFF0F000FFF0F0005F3F1F00FFF0F000AF773F000000
      000000000000000000000000000000000000AF773F00FFF0F0005F3F1F00FFF0
      F000FFF0F000FFF0F0005F3F1F00FFF0F0005F3F1F00FFF0F000AF773F000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000AF773F00FFF0F0005F3F1F005F3F
      1F00AF773F00FFF0F0005F3F1F005F3F1F00AF773F00FFF0F000AF773F000000
      000000000000000000000000000000000000AF773F00FFF0F000AF773F005F3F
      1F005F3F1F00FFF0F0005F3F1F00FFF0F0005F3F1F00FFF0F000AF773F000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000AF773F00FFF0F000FFF0F000FFF0
      F000FFF0F000FFF0F000FFF0F000FFF0F000FFF0F000FFF0F000AF773F000000
      000000000000000000000000000000000000AF773F00FFF0F000FFF0F000FFF0
      F000FFF0F000FFF0F000FFF0F000FFF0F000FFF0F000FFF0F000AF773F000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000AF773F00AF773F00AF773F00AF77
      3F00AF773F00AF773F00AF773F00AF773F00AF773F00AF773F00AF773F000000
      000000000000000000000000000000000000AF773F00AF773F00AF773F00AF77
      3F00AF773F00AF773F00AF773F00AF773F00AF773F00AF773F00AF773F000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000AF9F8FFF5F47
      2FFF5F472FFF5F472FFF5F472FFF5F472FFF5F472FFF5F472FFF5F472FFF5F47
      2FFF5F472FFF5F472FFF5F472FFF5F472FFF0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000DFF2FF369BE0FF9B63DFFFDC57E7FFF058E9FFF063E2FFDC9AE1FF9BDFF2
      FF36000000000000000000000000000000000000000000000000AF9F8FFFFFFF
      FFFFF0D8D0FFF0D8D0FFE0D0BFFFE0C8BFFFE0BFAFFFE0BFAFFFE0B79FFFD0AF
      9FFFD0A79FFFD0A78FFFD0977FFF5F472FFF0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000000000000000000000000000B2E3
      FF7653DFFFF663F7FFFF80FFFFFF85FFFFFF93FFFFFF91FFFFFF71FAFFFF57E2
      FFF6B1E3FF760000000000000000000000000000000000000000AF9F8FFFFFFF
      FFFFFFF8F0FFFFF0F0FFF0E8E0FFF0E8E0FFF0E0D0FFF0D8D0FFF0D8D0FFF0D0
      BFFFF0D0BFFFE0D0BFFFD09F8FFF5F472FFF0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000004F774FFF5F675FFF4F5F4FFF3F4F
      3FFF3F473FFF2F372FFF0000000000000000000000008F7F6FFF5F4F3FFF5F47
      2FFF5F472FFF5F472FFF5F472FFF000000000000000000000000ADE2FF774DE5
      FFFF5CF9FFFF39F6FFFF12F6FFFF07F8FFFF0AFAFFFF1BFBFFFF4DFAFFFF74FE
      FFFF56E8FFFFAEE2FF7400000000000000000000000000000000AF9F8FFFFFFF
      FFFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F
      8FFFBF9F8FFFBFA79FFFD0A78FFF5F472FFF0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000005F8F5FFF9FC89FFF7FA77FFF6F9F
      6FFF5F8F6FFF2F3F2FFF0000000000000000000000009F877FFFFFF8F0FFF0E0
      D0FFF0D0BFFFE0C8AFFF5F472FFF0000000000000000DAF1FF3344D9FFF83CF3
      FFFF07EDFFFF00EFFFFF00F2FFFF00F5FFFF00F6FFFF00F6FFFF00F4FFFF11F3
      FFFF58F9FFFF4ADBFFF8DAF1FF33000000000000000000000000AF9F8FFFFFFF
      FFFFFFF8FFFFFFF8F0FFFFF0F0FFF0F0F0FFF0E8E0FFF0E8E0FFF0E0D0FFF0D8
      D0FFF0D8D0FFF0D0BFFFD0A78FFF5F472FFF0000000000000000000000000000
      0000E2DAD640ADA49B90957F77F06F573FFF8F775FFFD6D0CA40000000000000
      0000000000000000000000000000000000005F976FFFAFD8BFFF9FD0AFFF8FBF
      8FFF7FA77FFF4F574FFF8F6F5FFF7F5F4FFF7F5F4FFFAF8F7FFFFFFFFFFFFFF0
      F0FFFFE8E0FFE0C8AFFF5F472FFF000000000000000084D8FF9D29E8FFFF04EA
      FFFF00EBFFFF00EEFFFF03F1FFFF07F2FFFF07F3FFFF03F3FFFF00F1FFFF00EF
      FFFF0EF0FFFF3DEEFFFF83D9FF9D000000000000000000000000AF9F8FFFFFFF
      FFFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F
      8FFFBF9F8FFFBFA79FFFD0A78FFF5F472FFF000000000000000000000000EAE2
      DE40C2B3AEA0BFA79FFFD0B79FFFD0AF9FFFAF8F7FFF6F573FFFD6D0CA400000
      0000000000000000000000000000000000006FA76FFFBFE0D0FFBFD8BFFF9FD0
      AFFF8FC89FFF5F675FFF000000007F674FFF00000000AF9F8FFFFFFFFFFFFFF8
      FFFFFFF8F0FFFFF0E0FF5F472FFF000000000000000040D1FFDD0AE7FFFF00E6
      FFFF0BEAFFFF26EFFFFF36F1FFFF3BF3FFFF3CF3FFFF39F3FFFF2AF1FFFF0EED
      FFFF00EAFFFF1EEEFFFF43D3FFDD000000000000000000000000AF9F8FFFFFFF
      FFFFFFFFFFFFFFFFFFFFFFF8FFFFFFF8F0FFFFF0F0FFF0F0E0FFF0E8E0FFF0E0
      E0FFF0E0D0FFF0D8D0FFD0AF9FFF5F472FFF000000000000000000000000DAC8
      BF90E0C8BFFFF0D8D0FFF0D0BFFFF0C8BFFFE0C8AFFFAF8F7FFF7F6F5FFF0000
      0000000000000000000000000000000000005F9F6FFF6FA76FFF6F9F6FFF5F97
      6FFF5F975FFF4F875FFF000000008F6F5FFF00000000BFA78FFFAF9F8FFFAF8F
      7FFF9F8F7FFF9F876FFF8F7F6FFF00000000000000001DD0FFF200E3FFFF17E6
      FFFF46EDFFFF53F0FFFF59F1FFFF5DF3FFFF5EF3FFFF5CF3FFFF59F2FFFF4DF0
      FFFF19EAFFFF05E9FFFF20D3FFF2000000000000000000000000AF9F8FFFFFFF
      FFFFBF9F8FFFBF9F8FFFFFFFFFFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F8FFFF0E8
      E0FFF0E0E0FFF0E0D0FFE0B7AFFF5F472FFF000000000000000000000000CAB7
      B0D0F0E8E0FFF0E8E0FFF0D8D0FFF0D0BFFFF0C8BFFFD0AF9FFF6F573FFF0000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000009F775FFF0000000000000000000000000000
      0000000000000000000000000000000000000000000016CDFFF209E2FFFF50EA
      FFFF66EEFFFF6DF0FFFF74F1FFFF78F2FFFF79F2FFFF77F2FFFF72F1FFFF6DF1
      FFFF5AEEFFFF0AE6FFFF16D0FFF2000000000000000000000000BFA78FFFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8F0FFFFF8F0FFFFF0F0FFF0E8
      E0FFF0E8E0FFF0E0E0FFE0BFAFFF5F472FFF000000000000000000000000C6B1
      AAE0F0F8F0FFFFF8F0FFF0E8E0FFF0D8D0FFF0D0BFFFD0B79FFF8F775FFF0000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000009F7F6FFF0000000000000000000000000000
      0000000000000000000000000000000000000000000025C9FFDD29E4FFFF75ED
      FFFF7DEFFFFF86F1FFFF8DF2FFFF91F3FFFF92F3FFFF90F3FFFF8BF2FFFF84F1
      FFFF7FF0FFFF32E8FFFF24CAFFDD000000000000000000000000BFA79FFFFFFF
      FFFFBF9F8FFFBF9F8FFFFFFFFFFFBF9F8FFFBF9F8FFFBF9F8FFFBF9F8FFFFFF0
      F0FFF0E8E0FFF0E8E0FFE0C8BFFF5F472FFF000000000000000000000000D6C7
      C2A0E0E0D0FFFFFFFFFFFFF8F0FFF0E8E0FFF0D8D0FFBF9F8FFFA49B92900000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000AF876FFF0000000000000000000000000000
      0000000000000000000000000000000000000000000062CFFF9D3AE0FFFF8DF0
      FFFF93F1FFFF9CF2FFFFA3F4FFFFA7F5FFFFA8F5FFFFA6F5FFFFA1F4FFFF9AF2
      FFFF98F3FFFF43E3FFFF62CFFF9D000000000000000000000000BFA79FFFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8FFFFFFF8F0FFFFF8
      F0FFF0F0F0FFF0E8E0FFE0C8BFFF5F472FFF000000000000000000000000EEE8
      E640CEBCB6C0E0E0D0FFF0F0F0FFF0E8E0FFD0BFAFFFAE9F9AA0DAD4CE400000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000AF8F7FFF00000000BFA78FFF5F4F3FFF5F47
      2FFF5F472FFF5F472FFF5F472FFF0000000000000000CCEEFF3329CAFFF89DF4
      FFFFA8F3FFFFAFF4FFFFB6F5FFFFBAF6FFFFBBF6FFFFB9F6FFFFB5F5FFFFAFF5
      FFFFA8F6FFFF31CDFFF8CCEDFF33000000000000000000000000BFA79FFFFFFF
      FFFF5F675FFF5F675FFF5F675FFF5F675FFF5F675FFF5F675FFF5F675FFF5F67
      5FFF5F675FFF9F979FFFE0D0BFFF5F472FFF0000000000000000000000000000
      0000EEE8E640D6C7C2A0CAB7B0D0CEBCAAC0CEC6BE80E2DCD640000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000BF977FFF00000000BFA79FFFFFF8F0FFF0E0
      D0FFF0D0BFFFE0C8AFFF5F472FFF00000000000000000000000088D8FF776ADC
      FFFFC3F9FFFFC4F7FFFFC7F7FFFFCAF7FFFFCBF7FFFFCAF7FFFFC8F8FFFFCCFB
      FFFF79DEFFFF8CD9FF7400000000000000000000000000000000BFAF9FFFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8
      FFFFFFF8F0FFFFF0F0FFF0D8D0FF5F472FFF0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000BF977FFFBF977FFFBFAF9FFFFFFFFFFFFFF0
      F0FFFFE8E0FFE0C8AFFF5F472FFF0000000000000000000000000000000089D8
      FF7876D7FFF6C7F4FFFFE1FDFFFFE5FDFFFFE6FDFFFFE4FDFFFFD0F7FFFF7DD9
      FFF68ED9FF760000000000000000000000000000000000000000D0AF9FFFFFFF
      FFFF5F675FFF5F675FFF5F675FFF5F675FFF5F675FFFFFFFFFFFFFFFFFFFFFFF
      FFFFFFF8FFFFFFF8F0FFF0E0D0FF5F472FFF0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000D0AF9FFFFFFFFFFFFFF8
      FFFFFFF8F0FFFFF0E0FF5F472FFF000000000000000000000000000000000000
      0000C9ECFF3679D3FF9B79D5FFDC8FDDFFF08FDDFFF07AD5FFDC7CD5FF9BC9EC
      FF36000000000000000000000000000000000000000000000000D0AF9FFFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFF5F472FFF0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000D0AF9FFFBFAF9FFFBFA7
      9FFFBFA79FFFBFA78FFFBF9F8FFF000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000D0AF9FFFD0B7
      9FFFD0B79FFFD0B79FFFD0AF9FFFBFAF9FFFBFAF9FFFBFAF9FFFBFAF9FFFBFA7
      9FFFBFA79FFFBFA78FFFBF9F8FFFAF9F8FFF0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000CED2FE367C8AFD9B6079FDDC6A87FEF06987FEF05F78FDDC7C8AFD9BCED2
      FE36000000000000000000000000000000000000000000000000000000000000
      0000D7F2DF3691DEAC9B70DC9DDC72E3A8F074E4ABF073DFA1DC92E0AD9BD7F2
      DF360000000000000000000000000000000000000000AFB0AFFFB0AFB0FFB0AF
      B0FFB0B0AFFFB0B0B0FFAFB0AFFFB0B0B0FFAFB0B0FFB0AFB0FFB0AFB0FFB0B0
      AFFFB0AFB0FFB0AFB0FFB0B0AFFF0000000000000000C4C1C1FFC3C0C0FFC2BF
      BFFFC1BEBEFFC0BDBDFFBFBCBBFFBFBBBBFFBDB9BAFFBCB9B9FFBBB8B8FFBAB7
      B7FFBBB6B6FFBAB5B5FFB9B5B5FF00000000000000000000000000000000959F
      FB76516BFBF685A5FEFFA4C6FFFFAFD1FFFFB0D2FFFFA5C6FFFF85A5FEFF506A
      FBF6959FFB76000000000000000000000000000000000000000000000000A9E2
      B9765CD78AF67BEBB3FF98F7D3FFA6FDE3FFACFFE9FFA3FDE0FF86F2C3FF63DA
      93F6A9E2B97600000000000000000000000000000000B3B3B3FFFFFFFFFFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
      FFFFFFFFFFFFFFFFFFFFB3B3B3FF0000000000000000C8C6C5FFFFFFFFFFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
      FFFFFFFFFFFFFFFFFFFFBBB7B7FF00000000000000000000000097A0F9744D67
      FAFF7B9AFDFF82A2FEFF80A4FEFF81A7FEFF81A6FEFF80A3FEFF84A4FEFF7C9B
      FDFF4D66FAFF96A0F97400000000000000000000000000000000A9E0B7744FD5
      7BFF6CE8A2FF77EEB3FF7AF3BDFF83FACDFF89FED9FF88FAD0FF87F5C7FF7CF0
      B7FF59DA8AFFAAE0B774000000000000000000000000B6B6B7FFFFFFFFFF0015
      F4FF2D4DF7FF0011F5FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0CBA45FF27CD
      68FF00BC41FFFFFFFFFFB7B6B6FF0000000000000000CCC9C9FFFFFFFFFFFEFD
      FDFFFEFDFDFFFEFDFDFFFEFDFDFFFEFDFDFFFEFDFDFFFEFDFDFFFEFDFDFFFEFD
      FDFFFEFDFDFFFFFFFFFFBDBAB9FF0000000000000000D0D4FB333C51F6F85F79
      FCFF6481FDFF698AFDFF7193FEFF7599FEFF7598FEFF7092FEFF6888FDFF6481
      FCFF5E79FCFF3B50F6F8D0D4FB330000000000000000D9F0DE3349C96AF84FDC
      7FFF5BE290FF63E99FFF6FF0B2FF78F6C1FF7CF8C8FF78F6C0FF6EEFB1FF67E9
      A3FF5EE494FF4ECD72F8D9F0DD330000000000000000B9B9B9FFFFFFFFFF0000
      DAFF1017F0FF0000CFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00A60EFF0BCF
      30FF00B000FFFFFFFFFFBABABAFF0000000000000000CFCDCEFFFFFFFFFFFCFB
      FBFFFCFBFBFFFCFBFBFFFCFBFBFFFCFBFBFFFCFBFBFFFCFBFBFFFCFBFBFFFCFB
      FBFFFCFBFBFFFFFFFFFFC0BCBDFF0000000000000000737EF39D475EFAFF546D
      FBFF5C77FCFF6381FDFF6888FDFF6B8BFDFF6B8BFDFF6787FDFF6280FCFF5A75
      FCFF526BFBFF465BF9FF737EF39D00000000000000008AD3969D40D064FF49D8
      76FF55DF87FF5FE598FF68EBA5FF6EEFB0FF71F1B4FF6EEFB0FF68EBA6FF5FE5
      97FF55DF88FF4AD775FF8BD3989D0000000000000000BDBCBCFFFFFFFFFF1211
      ACFF2523B5FF2F2DC8FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF60C053FF40AA
      33FF2F9F20FFFFFFFFFFBCBCBCFF0000000000000000D3D2D1FFFFFDFDFFFBF9
      F9FFFBF9F9FFFBF9F9FFFBF9F9FFFBF9F9FFFBF9F9FFFBF9F9FFFBF9F9FFFBF9
      F9FFFBF9F9FFFFFEFEFFC3C0C0FF00000000000000004250F0DD4459FBFF4B62
      FBFF536CFBFF5A75FCFF5F7CFCFF627FFCFF627FFCFF5E7AFCFF5973FBFF526B
      FBFF4A60FBFF4256FBFF424FF0DD000000000000000056C466DD39CF5CFF44D4
      6CFF4EDA7CFF57E08AFF5FE597FF64E89FFF66E9A1FF63E89EFF5EE496FF56E0
      8AFF4EDA7DFF44D66DFF59C66CDD0000000000000000C0C0BFFFFFFFFFFFFFFF
      FFFFA8A8A8FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA8A8
      A8FFFFFFFFFFFFFFFFFFC0C0BFFF0000000000000000D7D6D5FFFDFCFCFFF9F8
      F8FFF9F8F8FFF9F8F8FFF9F8F8FFF9F8F8FFF9F8F8FFF9F8F8FFF9F8F8FFF9F8
      F8FFF9F8F8FFFDFCFCFFC7C4C4FF0000000000000000323FEEF23C4EFBFF4357
      FAFF4E64FBFF5971FBFF607AFCFF647EFCFF647DFCFF5F77FCFF566DFBFF4A61
      FAFF4155FAFF3B4CFBFF303EEEF200000000000000003EBE4FF232CB51FF3DCF
      62FF4AD674FF57DC85FF60E191FF65E499FF66E49AFF62E396FF5ADF8CFF50DA
      7DFF45D56FFF3CD162FF44C257F20000000000000000C3C3C2FFFCFBFCFFFCFC
      FCFFA8A8A8FFA8A8A8FFA8A8A8FFA8A8A8FFA8A8A8FFA8A8A8FFA8A8A8FFA8A8
      A8FFFCFCFCFFFBFCFBFFC3C3C2FF0000000000000000DAD9D9FFFBFAFAFFF8F6
      F6FFF8F6F6FFF8F6F6FFF8F6F6FFF8F6F6FFF8F6F6FFF8F6F6FFF8F6F6FFF8F6
      F6FFF8F6F6FFFCFAFAFFCAC8C8FF00000000000000002B37ECF23443FBFF4355
      FAFF5368FBFF5F75FBFF667EFCFF6A81FCFF6981FCFF647BFCFF5B71FBFF4E62
      FAFF3E4FF9FF3240FBFF2B36ECF200000000000000003ABA46F22AC646FF3FCE
      60FF50D577FF5DDA88FF66DE93FF6BE199FF6BE19AFF68E095FF5FDC8BFF53D7
      7CFF42D167FF33CC54FF3FBE4FF20000000000000000C5C5C5FFF7F7F7FFF8F7
      F7FFF7F7F7FFF7F7F7FFF8F7F7FFA8A8A8FFA8A8A8FFF7F7F7FFF7F7F7FFF8F8
      F7FFF8F7F8FFF7F7F8FFC5C6C5FF0000000000000000DDDCDCFFF9F7F7FFF6F4
      F4FFF6F4F4FFF6F4F4FFF6F4F4FFF6F4F4FFF6F4F4FFF6F4F4FFF6F4F4FFF6F4
      F4FFF6F4F4FFFAF8F8FFCECDCCFF0000000000000000353EE5DD313DFBFF4A5B
      FAFF5A6DFAFF667AFBFF6E84FBFF7288FBFF7187FBFF6B81FBFF6176FBFF5467
      FAFF4353F9FF2C39FAFF343DE5DD00000000000000004AB94FDD29C342FF47CE
      66FF58D57BFF65DA8CFF6EDE98FF73E09DFF73E09DFF6EDF98FF65DB8EFF58D6
      7DFF47D069FF2FC74BFF4EBB54DD0000000000000000C7C8C8FFF1F2F2FFF2F2
      F2FFF2F1F2FFF2F2F2FFF28C33FFFFB86FFFFFB86FFFF28C31FFF1F2F2FFF2F2
      F2FFF2F2F2FFF2F2F2FFC7C8C8FF0000000000000000DFDFDFFFF7F9FEFFF4F6
      FBFFF4F6FBFFF4F6FBFFF4F6FBFFF5F6FBFFF5F7FBFFF5F7FBFFF5F7FCFFF5F7
      FCFFF5F7FCFFF9FBFFFFD2D1D0FF0000000000000000696EE29D2C37F6FF5061
      FBFF6073FBFF6D82FBFF778CFCFF7B92FCFF7A90FCFF7389FBFF697DFBFF5A6C
      FAFF4858FAFF2833F6FF696EE29D000000000000000082C77E9D2BBE3EFF4ECE
      6DFF5FD582FF6EDA94FF77DEA1FF7CE0A7FF7CE0A6FF76DF9FFF6CDB93FF5ED6
      81FF4CD06CFF2FC144FF83C8809D0000000000000000CACACAFFEDECECFFECEC
      ECFFECECECFFECECECFFEB6000FFE06E0DFFE06E0DFFEB6000FFECECEDFFECEC
      ECFFECEDECFFECECECFFCAC9CAFF0000000000000000EA994EFFEA994EFFEA99
      4FFFEA9A4EFFEB9A4EFFEB994EFFEA994EFFEB9A4EFFEA994EFFEA994EFFEA9A
      4EFFEA9A4EFFEA9A4EFFEA994FFF0000000000000000CDCEF3332129DFF85565
      FEFF687BFBFF778CFCFF8198FCFF879EFCFF859CFCFF7D94FCFF7185FBFF6072
      FBFF4C5BFDFF2028DFF8CDCFF3330000000000000000D8EBD43336B138F850D0
      71FF67D68CFF77DC9FFF82E0ADFF88E3B4FF87E2B3FF7FDFAAFF74DB9BFF63D6
      88FF4DD06EFF39B33DF8D8EBD4330000000000000000CBCBCBFFE6E6E7FFE7E7
      E7FFE7E7E7FFE7E7E7FFE7E7E7FFE7E7E6FFE7E7E7FFE6E7E7FFE7E7E7FFE7E7
      E7FFE7E7E6FFE7E7E7FFCBCBCBFF0000000000000000F2AD67FFF3AD67FFF3AE
      66FFF3AE67FFF3AD67FFF2AD67FFF3AD67FFF3AE67FFF3AD67FFF3AE67FFF3AE
      67FFF2AE67FFF3AD67FFF3AE67FF0000000000000000000000008A8DE0773B47
      E7FF7388FFFF8299FDFF8DA7FDFF94AEFDFF92ACFDFF88A0FDFF7A90FDFF6A7E
      FFFF3843E7FF8A8DE07700000000000000000000000000000000A2D098774ABE
      58FF70DA9BFF81E0AEFF8EE3BEFF96E6C7FF94E6C4FF8BE2B8FF7CDEA7FF6AD9
      93FF4ABE59FFA4D19B74000000000000000000000000CBCBCBFFCBCBCBFFCBCB
      CBFFCBCBCBFFCBCBCBFFCBCBCBFFCBCBCBFFCBCBCBFFCBCBCBFFCBCBCBFFCBCB
      CBFFCBCBCBFFCBCBCBFFCBCBCBFF0000000000000000F7AD73CCF9BC79FFF9BC
      79FFF9BC79FFF9BC79FFF9BC79FFF9BC79FFF9BC79FFF9BC79FFF9BC79FFF9BC
      79FFF9BC79FFF9BC79FFEBA061CC00000000000000000000000000000000898A
      DB784855DBF6829AFAFFA3C0FFFFAFCFFFFFABCAFFFF9AB6FFFF7B92FAFF4551
      DCF68A8CDC78000000000000000000000000000000000000000000000000A2CE
      967860BD69F685DDB1FFA1ECDBFFADF1EBFFAAF0E7FF99EAD1FF80DCAAFF5DBD
      67F6A4D099760000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000C9C9EC367175D29B616CD4DC7387DEF07082DEF05C68D3DC7275D39BC9C9
      EC36000000000000000000000000000000000000000000000000000000000000
      0000D4E7CD368FC5839B7DC381DC8ACEA0F087CD9DF079C17DDC8FC5839BD4E7
      CD36000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000424D3E000000000000003E000000
      2800000040000000300000000100010000000000800100000000000000000000
      000000000000000000000000FFFFFF00801F801F00000000001F001F00000000
      001F001F00000000001F001F00000000001F001F00000000001F001F00000000
      001F001F00000000001F001F00000000001F001F00000000FFFFFFFF00000000
      FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000
      FFFFFFFF00000000FFFFFFFF00000000FFFFC000FFFFFFFFF00FC000FFFFFFFF
      E007C000FFFF0381C003C000FFFF03818001C000F03F00018001C000E01F0281
      8001C000E01F02818001C000E01FFEFF8001C000E01FFEFF8001C000E01FFEFF
      8001C000E01FFE818001C000F03FFE81C003C000FFFFFE01E007C000FFFFFF81
      F00FC000FFFFFF81FFFFC000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00FF00F
      80018001E007E00780018001C003C00380018001800180018001800180018001
      8001800180018001800180018001800180018001800180018001800180018001
      8001800180018001800180018001800180018001C003C00380018001E007E007
      FFFFFFFFF00FF00FFFFFFFFFFFFFFFFF00000000000000000000000000000000
      000000000000}
  end
  object pmCopy: TPopupMenu
    OnPopup = pmCopyPopup
    Left = 72
    Top = 16
    object mnuGotoAddress: TMenuItem
      Caption = 'Go to Address'
      Default = True
      ShortCut = 13
      OnClick = mnuGotoAddressClick
    end
    object mnuSeparator1: TMenuItem
      Caption = '-'
    end
    object mnuCopyAddress: TMenuItem
      Caption = 'Copy Address'
      OnClick = mnuCopyAddressClick
    end
  end
end
