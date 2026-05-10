////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Resources.Helpers.pas
//  * Purpose   : Быстрый анализ типа ресурса по его содержимому.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.2.26
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Resources.Helpers;

interface

uses
  Windows,
  Classes,
  SysUtils,
  StrUtils,
  RawScanner.Resources;

const
  RC3_STOCKICON = 0;
  RC3_ICON = 1;
  RC3_CURSOR = 2;

  IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
  IMAGE_DOS_SIGNATURE = $5A4D;
  IMAGE_NT_SIGNATURE = $00004550;
  IMAGE_FILE_MACHINE_I386 = $14C;
  IMAGE_FILE_MACHINE_AMD64 = $8664;

  VS_FFI_STRUCVERSION = $10000;
  VS_FFI_FILEFLAGSMASK = 63;

  EMR_HEADER = 1;
  ENHMETA_SIGNATURE = $464D4520;

  PNG_SIGNATURE: array[0..7] of Byte = ($89, $50, $4E, $47, $0D, $0A, $1A, $0A);

  TiffHeader: array [0..2] of Byte = (73, 73, 42);
  Tiff2Header: array [0..2] of Byte = (77, 77, 42);
  WMFKey  = Integer($9AC6CDD7);

  FilerSignature: UInt32 = $30465054; // ($54, $50, $46, $30) 'TPF0'

  DLicHashAL1s: array[0..3] of UInt32 = (
    $FFFFFFF0, // Personal/Standard
    $FFFFEBF0, // Professional
    0,         // Enterprise
    $FFFFFFFF  // Invalid licence
  );


type
  {$ALIGN 4}

  DWORD = Cardinal;
  ULONGLONG = UInt64;
  SHORT = SmallInt;

  TCursorOrIcon = packed record
    Reserved: Word;
    wType: Word;
    Count: Word;
  end;

  TIconFileDirEntry = packed record
    Width: Byte;
    Height: Byte;
    ColorCount: Byte;
    Reserved: Byte;
    Planes: Word;     // для .cur: HotspotX
    BitCount: Word;   // для .cur: HotspotY
    BytesInRes: DWORD;
    ImageOffset: DWORD;
  end;

  TGrpIconEntry = packed record
    Width: Byte;
    Height: Byte;
    ColorCount: Byte;
    Reserved: Byte;
    Planes: Word;
    BitCount: Word;
    BytesInRes: DWORD;
    Id: Word;
  end;

  TGrpCursorEntry = packed record
    Width: Word;
    Height: Word;
    Planes: Word;
    BitCount: Word;
    BytesInRes: DWORD;
    Id: Word;
  end;

  _SMALL_RECT = record
    Left: SHORT;
    Top: SHORT;
    Right: SHORT;
    Bottom: SHORT;
  end;
  TSmallRect = _SMALL_RECT;

  _ENHMETAHEADER = record
    iType: DWORD;
    nSize: DWORD;
    rclBounds: TRect;
    rclFrame: TRect;
    dSignature: DWORD;
    nVersion: DWORD;
    nBytes: DWORD;
    nRecords: DWORD;
    nHandles: Word;
    sReserved: Word;
    nDescription: DWORD;
    offDescription: DWORD;
    nPalEntries: DWORD;
    szlDevice: TSize;
    szlMillimeters: TSize;
    cbPixelFormat: DWORD;
    offPixelFormat: DWORD;
    bOpenGL: DWORD;
    szlMicrometers: TSize;
  end;
  TEnhMetaHeader = _ENHMETAHEADER;

  TGIFHeaderRec = record
    Signature: array[0..2] of AnsiChar; { contains 'GIF' }
    Version: array[0..2] of AnsiChar;   { '87a' or '89a' }
  end;

  TMetafileHeader = record
    Key: Longint;
    Handle: SmallInt;
    Box: TSmallRect;
    Inch: Word;
    Reserved: Longint;
    CheckSum: Word;
  end;

  TPNGChunkHeader = packed record
    Length: Cardinal; // big-endian
    ChunkType: array[0..3] of AnsiChar;
  end;

  TPNGIHDRData = packed record
    Width: Cardinal;  // big-endian
    Height: Cardinal; // big-endian
    BitDepth:  Byte;
    ColorType: Byte;
  end;

type
  TBinaryResType = (brtUnknown,
    // ресурсы которые можно декодировать обратно в текстовое RC представление
    brtVersion, brtStringTable, brtAccelerator, brtMenu, brtDialog, brtFont, brtFontDir,
    // MessageTable - только частично, так как там не хранится строковое имя констант
    brtMessageTable,
    // Вся поддерживаемая графика
    brtCursorGroup, brtCursor, brtCursorDib, brtAniCursor,
    brtIconGroup, brtIcon, brtIconDib, brtAniIcon,
    brtBitmap, brtBitmapDib, brtPng, brtJpg, brtGif, brtMetaFile, brtTiff,
    // Все поддерживаемые форматы строк
    brtStrUtf8, brtStrUtf16, brtStrUtf16Be, brtStrAnsi,
    // Специальные типы ресурсов формат которых известен
    brtDVCLAL, brtDFM);

  function GetBinaryResType(ARes: TResource): TBinaryResType;

  // Для дампа, дабы не дублировать
  function GDAL(ALR: Pointer): UInt32;

implementation

function CheckBOM(AStream: TMemoryStream): TBinaryResType;
var
  BOM: Cardinal;
begin
  Result := brtUnknown;
  if AStream.Size < 4 then Exit;
  case PWord(AStream.Memory)^ of
    $FEFF: Result := brtStrUtf16;
    $FFFE: Result := brtStrUtf16Be;
  else
    BOM := 0;
    Move(AStream.Memory^, BOM, 3);
    if BOM = $BFBBEF then
      Result := brtStrUtf8;
  end;
end;

function CheckUtf8(AStream: TMemoryStream): TBinaryResType;
var
  P, EndP: PByte;
  TailCount: Integer;
begin
  Result := brtUnknown;
  P := AStream.Memory;
  EndP := P + AStream.Size;
  TailCount := 0;
  while P < EndP do
  begin

    // https://www.rfc-editor.org/rfc/rfc3629

    //  Char. number range  |        UTF-8 octet sequence
    //     (hexadecimal)    |              (binary)
    //  --------------------+---------------------------------------------
    //  0000 0000-0000 007F | 0xxxxxxx
    //  0000 0080-0000 07FF | 110xxxxx 10xxxxxx
    //  0000 0800-0000 FFFF | 1110xxxx 10xxxxxx 10xxxxxx
    //  0001 0000-0010 FFFF | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx

    if TailCount > 0 then
    begin
      // просто проверяем что вся последовательность байт
      // содержат старшими битами 10xxxxxx (т.е. UTF8-tail)
      if P^ and $C0 <> $80 then Exit;
      Inc(P);
      Dec(TailCount);
      Continue;
    end;

    // UTF8-1 = %x00-7F (ASCII символы)
    if P^ < $7F then
    begin
      // гарантировано не валидные для однобайтного ASCII символы
      if P^ in [0..8, 11, 12, 14..31] then Exit;
      Inc(P);
      Continue;
    end;

    // UTF8-2 = %xC2-DF UTF8-tail
    if P^ in [$C2..$DF] then
    begin
      TailCount := 1;
      Inc(P);
      Continue;
    end;

    // UTF8-3 = %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) /
    //          %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )
    if P^ and $F0 = $E0 then
    begin
      TailCount := 2;
      Inc(P);
      Continue;
    end;

    // UTF8-4 = %xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) /
    //          %xF4 %x80-8F 2( UTF8-tail )
    if P^ in [$F0..$F4] then
    begin
      TailCount := 3;
      Inc(P);
      Continue;
    end;

    // если байт не попадает ни в один из диапазонов, это не UTF8
    Exit;

  end;

  Result := brtStrUtf8;
end;

function IsValidUTF16CodePoint(ACodePoint: Word): Boolean;
begin
  case ACodePoint of
    $0009,
    $000A,
    $000D,
    $0020..$007E, // английский
    $00A0..$024F, // часть латиницы немецкий, французский и т.п.(ä,ö,é,à,ñ,ą,ę)
    $0300..$036F, // польский чешский диактрики
    $0370..$03FF, // греческий
    $0400..$04FF, // кирилица
    $2000..$206F, // типографика
    $20A0..$20CF, // валюты
    $2100..$23FF: // вспомогательные типа №, ℅ и др.
      Result := True;
  else
    Result := False;
  end;
end;

function CheckUtf16(AStream: TMemoryStream): TBinaryResType;
var
  P, EndP: PByte;
begin
  Result := brtUnknown;
  if AStream.Size and 1 = 1 then Exit;
  P := AStream.Memory;
  EndP := P + AStream.Size;
  while P < EndP do
  begin
    if not IsValidUTF16CodePoint(PWord(P)^) then Exit;
    Inc(P, 2);
  end;
  Result := brtStrUtf16;
end;

function CheckUtf16BE(AStream: TMemoryStream): TBinaryResType;
var
  P, EndP: PByte;
begin
  Result := brtUnknown;
  if AStream.Size and 1 = 1 then Exit;
  P := AStream.Memory;
  EndP := P + AStream.Size;
  while P < EndP do
  begin
    if not IsValidUTF16CodePoint((P^ shl 8) or (PWord(P)^ shr 8)) then Exit;
    Inc(P, 2);
  end;
  Result := brtStrUtf16Be;
end;

function CheckAnsi(AStream: TMemoryStream): TBinaryResType;
var
  P, EndP: PByte;
begin
  Result := brtUnknown;
  P := AStream.Memory;
  EndP := P + AStream.Size;
  while P < EndP do
  begin
    if P^ in [0..8, 11, 12, 14..31] then Exit;
    Inc(P);
  end;
  Result := brtStrAnsi;
end;

function CheckStringStream(AStream: TMemoryStream): TBinaryResType;
begin
  Result := CheckBOM(AStream);
  if Result <> brtUnknown then Exit;
  Result := CheckUtf8(AStream);
  if Result <> brtUnknown then Exit;
  Result := CheckUtf16(AStream);
  if Result <> brtUnknown then Exit;
  Result := CheckUtf16BE(AStream);
  if Result <> brtUnknown then Exit;
  Result := CheckAnsi(AStream);
end;

function AL1(const P): UInt32;
type
  List = array[0..3] of DWORD;
begin
  Result := List(P)[0];
  Result := Result xor List(P)[1];
  Result := Result xor List(P)[2];
  Result := Result xor List(P)[3];
end;

function AL2(const P): UInt32;
type
  List = array[0..3] of DWORD;
begin
  Result := List(P)[0];
  Result := (Result shr 5) or (Result shl 27);
  Result := Result xor List(P)[1];
  Result := (Result shr 5) or (Result shl 27);
  Result := Result xor List(P)[2];
  Result := (Result shr 5) or (Result shl 27);
  Result := Result xor List(P)[3];
end;

function GDAL(ALR: Pointer): UInt32;
type
  TDVCLAL = array[0..3] of UInt32;
  PDVCLAL = ^TDVCLAL;
const
  AL2s: array[0..3] of UInt32 = ($42C3ECEF, $20F7AEB6, $D1C2F74E, $3F6574DE);
var
  A1, A2: UInt32;
  ALOK: Boolean;
begin
  Result := 1;
  if ALR <> nil then
  begin
    A1 := AL1(ALR^);
    A2 := AL2(ALR^);
    ALOK := ((A1 = DLicHashAL1s[0]) and (A2 = AL2s[0])) or
            ((A1 = DLicHashAL1s[1]) and (A2 = AL2s[1])) or
            ((A1 = DLicHashAL1s[2]) and (A2 = AL2s[2]));
    if ALOK then
      Result := A1;
  end;
end;

function CheckDVCLAL(AStream: TMemoryStream): TBinaryResType;
begin
  Result := brtUnknown;
  if AStream.Size <> 16 then Exit;
  // Ноль это валидное значение для энтерпрайза, поэтому ошибкой будет единица
  if GDAL(AStream.Memory) <> 1 then
    Exit(brtDVCLAL);
end;

function GetBinaryResType(ARes: TResource): TBinaryResType;

  function ComputeAldusChecksum(const WMF: TMetafileHeader): Word;
  begin
    Result := 0;
    with WMF, Box do
    begin
      Result := Result xor Word(Key);
      Result := Result xor HiWord(Key);
      Result := Result xor Word(Handle);
      Result := Result xor Word(Left);
      Result := Result xor Word(Top);
      Result := Result xor Word(Right);
      Result := Result xor Word(Bottom);
      Result := Result xor Inch;
      Result := Result xor Word(Reserved);
      Result := Result xor HiWord(Reserved);
    end;
  end;

var
  ci: TCursorOrIcon;
  Ico: TIconFileDirEntry;
  Bmf: TBitmapFileHeader;
  ByteHeader: array[0..7] of AnsiChar;
  FilerSign: UInt32;
  soi, marker: Word;
  GifHeader: TGIFHeaderRec;
  Emh: TEnhMetaHeader;
  Wmf: TMetafileHeader;
  ResId: ULONG;
begin
  Result := brtUnknown;
  if ARes.Data = nil then Exit;
  ARes.Data.Position := 0;
  ResId := GetResType(ARes).Id;

  if ARes.Data.Read(ci, SizeOf(ci)) = SizeOf(ci) then
  begin
    if (ci.Reserved = 0) and (ci.Count > 0) then
    begin
      {$message 'не протестировано!!!'}
      if ARes.Data.Read(Ico, SizeOf(Ico)) = SizeOf(Ico) then
        if Ico.ImageOffset = SizeOf(ci) + SizeOf(Ico) * ci.Count then
        begin
          if (ci.wType = rc3_Icon) and (ResId <> ULONG(RT_GROUP_ICON)) then
            Exit(brtIcon);
          if (ci.wType = rc3_Cursor) and (ResId <> ULONG(RT_GROUP_CURSOR)) then
            Exit(brtCursor);
        end;
    end;
  end;

  ARes.Data.Position := 0;
  if (ARes.Data.Read(Bmf, SizeOf(Bmf)) = SizeOf(Bmf)) and
    (Bmf.bfType = $4D42) then
    Exit(brtBitmap);

  ARes.Data.Position := 0;
  if (ARes.Data.Read(ByteHeader[0], SizeOf(PNG_SIGNATURE)) = SizeOf(PNG_SIGNATURE)) and
    CompareMem(@ByteHeader[0], @PNG_SIGNATURE[0], SizeOf(PNG_SIGNATURE)) then
    Exit(brtPng);

  ARes.Data.Position := 0;
  if (ARes.Data.Read(soi, SizeOf(soi)) = SizeOf(soi)) and (soi = $D8FF) and
    (ARes.Data.Read(marker, SizeOf(marker)) = SizeOf(marker)) and
    ((marker and $E0FF = $E0FF) or (marker = $DBFF)) then
    Exit(brtJpg);

  ARes.Data.Position := 0;
  if (ARes.Data.Read(GifHeader, SizeOf(GifHeader)) = SizeOf(GifHeader)) and
    (UpperCase(string(GifHeader.Signature)) = 'GIF') then
    Exit(brtGif);

  ARes.Data.Position := 0;
  if (ARes.Data.Read(Emh, SizeOf(Emh)) = SizeOf(Emh)) and
    (Emh.iType = EMR_HEADER) and (Emh.dSignature = ENHMETA_SIGNATURE) and
    (ARes.Data.Read(Wmf, SizeOf(Wmf)) = SizeOf(Wmf)) and
    (Wmf.Key = WMFKey) and (ComputeAldusChecksum(Wmf) = Wmf.CheckSum) then
    Exit(brtMetaFile);

  ARes.Data.Position := 0;
  if (ARes.Data.Read(ByteHeader[0], SizeOf(TiffHeader)) = SizeOf(TiffHeader)) and
    (CompareMem(@ByteHeader[0], @TiffHeader[0], Length(TiffHeader)) or
     CompareMem(@ByteHeader[0], @Tiff2Header[0], Length(Tiff2Header))) then
    Exit(brtTiff);

  ARes.Data.Position := 0;
  if (ARes.Data.Read(FilerSign, SizeOf(FilerSign)) = SizeOf(FilerSign)) and
    (FilerSign = FilerSignature) then
    Exit(brtDFM);

  ARes.Data.Position := 0;
  Result := CheckDVCLAL(ARes.Data);
  if Result <> brtUnknown then Exit;

  ARes.Data.Position := 0;
  Result := CheckStringStream(ARes.Data);
  if Result <> brtUnknown then Exit;

  case ResId of
    ULONG(RT_VERSION): Result := brtVersion;
    ULONG(RT_STRING): Result := brtStringTable;
    ULONG(RT_MESSAGETABLE): Result := brtMessageTable;
    ULONG(RT_MENU), ULONG(RT_MENUEX): Result := brtMenu;
    ULONG(RT_ACCELERATOR): Result := brtAccelerator;
    ULONG(RT_DIALOG), ULONG(RT_DIALOGEX): Result := brtDialog;
    ULONG(RT_FONT): Result := brtFont;
    ULONG(RT_FONTDIR): Result := brtFontDir;
    ULONG(RT_BITMAP): Result := brtBitmapDib;
    ULONG(RT_ICON): Result := brtIconDib;
    ULONG(RT_CURSOR): Result := brtCursorDib;
    ULONG(RT_GROUP_ICON): Result := brtIconGroup;
    ULONG(RT_GROUP_CURSOR): Result := brtCursorGroup;
  end;
end;

end.
