////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Unit Name : FWAniPaintBox.pas
//  * Purpose   : Animation Viewer in the RIFF Container (AVI, ANICURSOR)
//  * Author    : Alexander (Rouse_) Bagel
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.0
//  ****************************************************************************
//

// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/um/aviriff.h
// https://techshelps.github.io/MSDN/CODE0X07/devdoc/good/code/sdktools/aniedit/c5381_8qwj.htm

unit FWAniPaintBox;

interface

uses
  Windows,
  Classes,
  SysUtils,
  Controls,
  ExtCtrls,
  Graphics,
  StrUtils,
  Math,
  Types;

{
/*
 * heres the general layout of an AVI riff file (new format)
 *
 * RIFF (3F??????) AVI       <- not more than 1 GB in size
 *     LIST (size) hdrl
 *         avih (0038)
 *         LIST (size) strl
 *             strh (0038)
 *             strf (????)
 *             indx (3ff8)   <- size may vary, should be sector sized
 *         LIST (size) strl
 *             strh (0038)
 *             strf (????)
 *             indx (3ff8)   <- size may vary, should be sector sized
 *         LIST (size) odml
 *             dmlh (????)
 *         JUNK (size)       <- fill to align to sector - 12
 *     LIST (7f??????) movi  <- aligned on sector - 12
 *         00dc (size)       <- sector aligned
 *         01wb (size)       <- sector aligned
 *         ix00 (size)       <- sector aligned
 *     idx1 (00??????)       <- sector aligned
 * RIFF (7F??????) AVIX
 *     JUNK (size)           <- fill to align to sector -12
 *     LIST (size) movi
 *         00dc (size)       <- sector aligned
 * RIFF (7F??????) AVIX      <- not more than 2GB in size
 *     JUNK (size)           <- fill to align to sector - 12
 *     LIST (size) movi
 *         00dc (size)       <- sector aligned
 *
 *-===================================================================*/
}

type
  TFourCC = array [0..3] of AnsiChar;

  TRiffChunk = packed record
    ID: TFourCC;
    Size: DWORD;
  end;

  TAniHeader = packed record
    cbSizeOf,
    cFrames,
    cSteps,
    cx, cy,
    cBitCount, cPlanes,
    JifRate,
    flags: DWORD;
  end;

  TAviMainHeader = packed record
    // there's also TRiffChunk here,
    // but it's read separately during the tree traversal
    dwMicroSecPerFrame,
    dwMaxBytesPerSec,
    dwPaddingGranularity,
    dwFlags,
    dwTotalFrames,
    dwInitialFrames,
    dwStreams,
    dwSuggestedBufferSize,
    dwWidth,
    dwHeight: DWORD;
    dwReserved: array [0..3] of DWORD;
  end;

  TAniBackgroundMode = (abmTransparent, abmFillColor, abmGrayChecker);
  TAniStretchMode = (asmCenter, asmStretch);
  TAniPaintKind = (pkNone, pkAniCursor, pkAVI);

  TRiffIcon = record
    Icons: array of HICON;
    Rate: array of DWORD;
    Seq: array of Integer;
  end;

  TRiffAvi = record
    Width: Integer;
    Height: Integer;
    Header: TBitmapInfoHeader;
    FullFrameSize: Integer;
    Palette: array of TRGBQuad;
    Frames: array of TBytes;
    FrameRateMs: DWORD;
    Bitmaps: array of HBITMAP;
  end;

  EAnimateException = class(Exception);

  TCustomAniPaintBox = class(TGraphicControl)
  private
    FActive: Boolean;
    FAniCursorIcon: TRiffIcon;
    FAvi: TRiffAvi;
    FBackgroundMode: TAniBackgroundMode;
    FDefaultRateMs: DWORD;
    FFillColor: TColor;
    FFrameIdx: Integer;
    FFrameTimer: TTimer;
    FInvalidateRect: TRect;
    FKind: TAniPaintKind;
    FLoaded: Boolean;
    FShowInfo: Boolean;
    FStretchMode: TAniStretchMode;
    FTransparentColor: TColor;
    procedure AutoDetectTransparentColor;
    procedure BuildAviBitmaps;
    function ConvertFrameTo24(const Src: TBytes; Width, Height, BitCount: Integer): TBytes;
    function DecodeRLE8(const Compressed: TBytes; Width, Height: Integer; const PrevFrame: TBytes): TBytes;
    procedure DrawCheckerBoard(CheckerSize: Integer; const ARect: TRect);
    procedure FreeFrames;
    procedure PaintAniFrame;
    procedure PaintAviFrame;
    procedure PaintBackground(X, Y, W, H: Integer);
    procedure PaintNewFrame(Sender: TObject);
    function ParseAniStream(Stream: TStream; RiffDataSize: DWORD): TAniPaintKind;
    function ParseAviStream(Stream: TStream; RiffDataSize: DWORD): TAniPaintKind;
    procedure SetActive(Value: Boolean);
    procedure SetBackgroundMode(const Value: TAniBackgroundMode);
    procedure SetFillColor(const Value: TColor);
    procedure SetStretchMode(Value: TAniStretchMode);
    procedure SetShowInfo(const Value: Boolean);
  protected
    procedure Paint; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure LoadFromStream(Stream: TStream);
    procedure Play;
    procedure Stop;
  protected
    property Active: Boolean read FActive write SetActive default False;
    property BackgroundMode: TAniBackgroundMode read FBackgroundMode write SetBackgroundMode default abmGrayChecker;
    property FillColor: TColor read FFillColor write SetFillColor default clWhite;
    property ShowInfo: Boolean read FShowInfo write SetShowInfo default True;
    property StretchMode: TAniStretchMode read FStretchMode write SetStretchMode default asmCenter;
  end;

  TFWAniPaintBox = class(TCustomAniPaintBox)
  published
    property Active;
    property Align;
    property Anchors;
    property BackgroundMode;
    property Color;
    property FillColor;
    property PopupMenu;
    property ShowInfo;
    property StretchMode;
    property Visible;
    property OnClick;
    property OnDblClick;
    property OnMouseDown;
    property OnMouseUp;
    property OnMouseMove;
  end;

implementation

{ TCustomAniPaintBox }

constructor TCustomAniPaintBox.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  Width := 32;
  Height := 32;
  FBackgroundMode := abmGrayChecker;
  FDefaultRateMs := 66;
  FFillColor := clWhite;
  FFrameTimer := TTimer.Create(Self);
  FFrameTimer.Enabled := False;
  FFrameTimer.OnTimer := PaintNewFrame;
  FShowInfo := True;
  FStretchMode := asmCenter;
end;

destructor TCustomAniPaintBox.Destroy;
begin
  FFrameTimer.Enabled := False;
  FreeFrames;
  inherited;
end;

procedure TCustomAniPaintBox.DrawCheckerBoard(CheckerSize: Integer;
  const ARect: TRect);
var
  X, Y: Integer;
  GraySquare: Boolean;
begin
  Canvas.Brush.Style := bsSolid;
  Y := ARect.Top;
  while Y < ARect.Bottom do
  begin
    X := ARect.Left;
    GraySquare := ((Y - ARect.Top) div CheckerSize) mod 2 = 0;
    while X < ARect.Right do
    begin
      if GraySquare then
        Canvas.Brush.Color := $F0F0F0
      else
        Canvas.Brush.Color := clWhite;
      Canvas.FillRect(Rect(X, Y, Min(X + CheckerSize, ARect.Right),
        Min(Y + CheckerSize, ARect.Bottom)));
      GraySquare := not GraySquare;
      Inc(X, CheckerSize);
    end;
    Inc(Y, CheckerSize);
  end;
  Canvas.Pen.Color := $00FCA000;
  Canvas.Brush.Style := bsClear;
  Canvas.Rectangle(ARect);
end;

procedure TCustomAniPaintBox.FreeFrames;
var
  I: Integer;
begin
  for I := 0 to Length(FAniCursorIcon.Icons) - 1 do
    if FAniCursorIcon.Icons[I] <> 0 then
      DestroyIcon(FAniCursorIcon.Icons[I]);
  FAniCursorIcon := Default(TRiffIcon);

  for I := 0 to Length(FAvi.Bitmaps) - 1 do
    if FAvi.Bitmaps[I] <> 0 then
      DeleteObject(FAvi.Bitmaps[I]);
  FAvi := Default(TRiffAvi);

  FFrameIdx := 0;
  FLoaded := False;
  FKind := pkNone;
end;

procedure TCustomAniPaintBox.LoadFromStream(Stream: TStream);
var
  Chunk: TRiffChunk;
  FormType: TFourCC;
begin
  Stop;
  FreeFrames;

  Stream.Position := 0;
  Stream.ReadBuffer(Chunk, SizeOf(TRiffChunk));
  if Chunk.ID <> 'RIFF' then
    raise EAnimateException.Create('RIFF signature is missing');

  Stream.ReadBuffer(FormType, SizeOf(TFourCC));
  case IndexStr(string(FormType), ['ACON', 'AVI ']) of
    0: FKind := ParseAniStream(Stream, Chunk.Size);
    1: FKind := ParseAviStream(Stream, Chunk.Size);
  else
    raise EAnimateException.Create('Unknown RIFF format (ACON or AVI was expected)');
  end;

  FLoaded := True;
end;

function TCustomAniPaintBox.ParseAniStream(Stream: TStream; RiffDataSize: DWORD): TAniPaintKind;
const
  AF_ICON = $0001;
var
  Chunk: TRiffChunk;
  Header: TAniHeader;
  EndPos, ListEnd: Int64;
  ListType: TFourCC;
  I, Idx: Integer;
  RawIcon: TMemoryStream;
  AnihPresent: Boolean;
begin
  AnihPresent := False;
  Idx := 0;

  EndPos := Stream.Position + (RiffDataSize - SizeOf(TFourCC));

  while Stream.Position < EndPos do
  begin
    Stream.ReadBuffer(Chunk, SizeOf(TRiffChunk));

    case IndexStr(string(Chunk.ID), ['anih', 'rate', 'seq ', 'LIST']) of
      0:
      begin
        Stream.ReadBuffer(Header, SizeOf(TAniHeader));
        AnihPresent := True;
        if (Header.flags and AF_ICON) = 0 then
          raise EAnimateException.Create(
            'Legacy .ani format without AF_ICON (raw MPTR frames) is not supported');
        SetLength(FAniCursorIcon.Icons, Header.cFrames);
        FDefaultRateMs := Round(Header.JifRate * 1000 / 60);
        if Header.cbSizeOf < SizeOf(Header) then
          Stream.Seek(SizeOf(Header) - Header.cbSizeOf, soFromCurrent);
      end;
      1:
      begin
        SetLength(FAniCursorIcon.Rate, Chunk.Size div SizeOf(DWORD));
        Stream.ReadBuffer(FAniCursorIcon.Rate[0], Chunk.Size);
        for I := 0 to Length(FAniCursorIcon.Rate) - 1 do
          FAniCursorIcon.Rate[I] := Round(FAniCursorIcon.Rate[I] * 1000 / 60);
      end;
      2:
      begin
        SetLength(FAniCursorIcon.Seq, Chunk.Size div SizeOf(DWORD));
        Stream.ReadBuffer(FAniCursorIcon.Seq[0], Chunk.Size);
      end;
      3:
      begin
        ListEnd := Stream.Position + Chunk.Size - SizeOf(TFourCC);
        Stream.ReadBuffer(ListType, SizeOf(TFourCC));
        if ListType = 'fram' then
        begin
          while Stream.Position < ListEnd do
          begin
            Stream.ReadBuffer(Chunk, SizeOf(Chunk));
            if Chunk.ID = 'icon' then
            begin
              RawIcon := TMemoryStream.Create;
              try
                RawIcon.CopyFrom(Stream, Chunk.Size);
                RawIcon.Position := 0;
                SetLength(FAniCursorIcon.Icons, Idx + 1);
                FAniCursorIcon.Icons[Idx] := CreateIconFromResourceEx(
                  PByte(PByte(RawIcon.Memory) + SizeOf(TCursorOrIcon) + SizeOf(TIconRec)),
                  RawIcon.Size, True, $00030000, 0, 0, LR_DEFAULTCOLOR);
                Inc(Idx);
              finally
                RawIcon.Free;
              end;
              if Chunk.Size mod 2 = 1 then
                Stream.Seek(1, soFromCurrent);
            end
            else
              Stream.Seek(Chunk.Size + (Chunk.Size mod 2), soFromCurrent);
          end;
        end
        else
          Stream.Seek(Chunk.Size - SizeOf(TFourCC), soFromCurrent);

        if ListType = 'fram' then
          if Stream.Position < ListEnd then
            Stream.Seek(ListEnd - Stream.Position, soFromCurrent);

        if Chunk.Size mod 2 = 1 then
          Stream.Seek(1, soFromCurrent);
      end;
    else
      Stream.Seek(Chunk.Size + (Chunk.Size mod 2), soFromCurrent);
    end;
  end;

  if not AnihPresent then
    raise EAnimateException.Create('The “anih” chunk is missing from the stream');

  if Length(FAniCursorIcon.Seq) = 0 then
  begin
    SetLength(FAniCursorIcon.Seq, Length(FAniCursorIcon.Icons));
    for I := 0 to Length(FAniCursorIcon.Seq) - 1 do
      FAniCursorIcon.Seq[I] := I;
  end;

  Result := pkAniCursor;
end;

function TCustomAniPaintBox.DecodeRLE8(const Compressed: TBytes; Width, Height: Integer;
  const PrevFrame: TBytes): TBytes;
var
  Stride: Integer;
  Src, SrcEnd: PByte;
  DstLine: PByte;
  X, Y: Integer;
  B1, B2: Byte;
  I: Integer;

  function GetSrcInc: Byte;
  begin
    Result := Src^;
    Inc(Src);
  end;

begin
  Stride := ((Width + 3) div 4) * 4;
  SetLength(Result, Stride * Height);

  // RLE8 frames in AVI can only encode CHANGES relative to the previous frame
  // (the delta-escape sequence 0,2,dx,dy simply shifts the cursor without
  // erasing any pixels). Therefore, we don't start with a blank canvas,
  // but rather with the content of the previous completed frame.

  if PrevFrame = nil then
    FillChar(Result[0], Length(Result), 0)
  else
    Move(PrevFrame[0], Result[0], Length(Result));

  if Length(Compressed) = 0 then
    Exit;

  Src := @Compressed[0];
  SrcEnd := Src + Length(Compressed);
  X := 0;
  Y := 0;
  DstLine := @Result[0];

  while Src < SrcEnd do
  begin
    B1 := GetSrcInc;
    if Src >= SrcEnd then Break;
    B2 := GetSrcInc;

    case B1 of
      0:
      begin
        case B2 of

          0: // End of line
          begin
            Inc(Y);
            if Y < Height then
              DstLine := @Result[Y * Stride]
            else
              Break;
            X := 0;
          end;

          // End of bitmap
          1: Break;

          // Delta.
          // The 2 bytes following the escape contain unsigned values indicating
          // the offset to the right and up of the next pixel from the current position.
          2:
          begin
            if Src + 1 < SrcEnd then
            begin
              X := X + GetSrcInc;
              Y := Y + GetSrcInc;
              if Y < Height then
                DstLine := @Result[Y * Stride]
              else
                Break;
            end;
          end;
        else
          // In absolute mode, the first byte is zero and the second byte is
          // a value in the range 03H through FFH. The second byte represents
          // the number of bytes that follow,
          // each of which contains the color index of a single pixel.
          for I := 0 to B2 - 1 do
          begin
            if Src >= SrcEnd then Break;
            if X < Width then
              DstLine[X] := Src^
            else
              Beep;
            Inc(X);
            Inc(Src);
          end;
          if (B2 and 1) = 1 then
            Inc(Src);
        end;
      end;
    else
      // In encoded mode, the first byte of the pair contains the number
      // of pixels to be drawn using the color indexes in the second byte.
      for I := 0 to B1 - 1 do
      begin
        if X < Width then
          DstLine[X] := B2
        else
          Beep;
        Inc(X);
      end;
    end;
  end;
end;

function TCustomAniPaintBox.ConvertFrameTo24(const Src: TBytes; Width, Height, BitCount: Integer): TBytes;
var
  SrcStride, DstStride: Integer;
  X, Y: Integer;
  SrcRow, DstRow: PByte;
  PalIdx: Byte;
begin
  DstStride := ((Width * 3 + 3) div 4) * 4;
  SetLength(Result, DstStride * Height);
  if Length(Result) = 0 then Exit;
  FillChar(Result[0], Length(Result), 0);

  case BitCount of
    8:
    begin
      SrcStride := ((Width + 3) div 4) * 4;
      for Y := 0 to Height - 1 do
      begin
        if (Y + 1) * SrcStride > Length(Src) then Break;
        SrcRow := @Src[Y * SrcStride];
        DstRow := @Result[Y * DstStride];
        for X := 0 to Width - 1 do
        begin
          PalIdx := SrcRow[X];
          if PalIdx < Length(FAvi.Palette) then
          begin
            DstRow[X * 3] := FAvi.Palette[PalIdx].rgbBlue;
            DstRow[X * 3 + 1] := FAvi.Palette[PalIdx].rgbGreen;
            DstRow[X * 3 + 2] := FAvi.Palette[PalIdx].rgbRed;
          end;
        end;
      end;
    end;
    24:
    begin
      if Length(Src) = Length(Result) then
        Move(Src[0], Result[0], Length(Result));
    end;
    32:
    begin
      SrcStride := Width * 4;
      for Y := 0 to Height - 1 do
      begin
        if (Y + 1) * SrcStride > Length(Src) then Break;
        SrcRow := @Src[Y * SrcStride];
        DstRow := @Result[Y * DstStride];
        for X := 0 to Width - 1 do
        begin
          DstRow[X * 3] := SrcRow[X * 4];         // B
          DstRow[X * 3 + 1] := SrcRow[X * 4 + 1]; // G
          DstRow[X * 3 + 2] := SrcRow[X * 4 + 2]; // R
          // Альфу пока что отбрасываем, не на чем тестировать,
          // по идее тут нужна премультипликация, но таких AVI я не нашел
        end;
      end;
    end;
  end;
end;

procedure TCustomAniPaintBox.BuildAviBitmaps;
var
  I: Integer;
  Bits: Pointer;
  FrameBytes: TBytes;
  DispBI: TBitmapInfo;
begin
  SetLength(FAvi.Bitmaps, Length(FAvi.Frames));
  FillChar(DispBI, SizeOf(DispBI), 0);
  DispBI.bmiHeader := FAvi.Header;
  DispBI.bmiHeader.biBitCount := 24;
  DispBI.bmiHeader.biCompression := BI_RGB;
  DispBI.bmiHeader.biSizeImage := 0;
  DispBI.bmiHeader.biClrUsed := 0;
  DispBI.bmiHeader.biClrImportant := 0;

  for I := 0 to Length(FAvi.Frames) - 1 do
  begin
    Bits := nil;
    FrameBytes := ConvertFrameTo24(FAvi.Frames[I], FAvi.Width, FAvi.Height, FAvi.Header.biBitCount);
    FAvi.Bitmaps[I] := CreateDIBSection(0, DispBI, DIB_RGB_COLORS, Bits, 0, 0);
    if (FAvi.Bitmaps[I] <> 0) and (Bits <> nil) and (Length(FrameBytes) > 0) then
      Move(FrameBytes[0], Bits^, Length(FrameBytes));
  end;
end;

procedure TCustomAniPaintBox.AutoDetectTransparentColor;
var
  MemDC: HDC;
  OldBmp: HBITMAP;
  AColor: COLORREF;
begin
  if (Length(FAvi.Bitmaps) = 0) or (FAvi.Bitmaps[0] = 0) then Exit;
  MemDC := CreateCompatibleDC(0);
  if MemDC = 0 then Exit;
  try
    OldBmp := SelectObject(MemDC, FAvi.Bitmaps[0]);
    try
      AColor := GetPixel(MemDC, 0, 0);
      if AColor <> CLR_INVALID then
        FTransparentColor := TColor(AColor);
    finally
      SelectObject(MemDC, OldBmp);
    end;
  finally
    DeleteDC(MemDC);
  end;
end;

function TCustomAniPaintBox.ParseAviStream(Stream: TStream; RiffDataSize: DWORD): TAniPaintKind;
const
  // vfw.h
  ckidAVIMAINHDR = 'avih';
  ckidSTREAMHEADER = 'strh';
  ckidSTREAMFORMAT = 'strf';
  streamtypeVIDEO =  'vids';
var
  EndPos: Int64;
  AviHeader: TAviMainHeader;
  AviHeaderPresent, StrfPresent, IsVideoStream: Boolean;

  procedure WalkChunks(StartEnd: Int64);
  var
    Chunk: TRiffChunk;
    ListType: TFourCC;
    ListEnd: Int64;
    FrameData: TBytes;
    FrameIdx, PalCount, PalBytesInChunk: Integer;
  begin
    while Stream.Position < StartEnd do
    begin
      Stream.ReadBuffer(Chunk, SizeOf(Chunk));

      case IndexStr(string(Chunk.ID), ['LIST', ckidAVIMAINHDR, ckidSTREAMHEADER, ckidSTREAMFORMAT]) of
        0: // List Node
        begin
          ListEnd := Stream.Position + Chunk.Size - SizeOf(TFourCC);
          Stream.ReadBuffer(ListType, SizeOf(TFourCC));
          WalkChunks(ListEnd);
          Stream.Position := Max(ListEnd, Stream.Position);
          if Chunk.Size mod 2 = 1 then
            Stream.Seek(1, soFromCurrent);
        end;
        1: // AVI Main Header
        begin
          Stream.ReadBuffer(AviHeader, SizeOf(AviHeader));

          {
            That's how it was in the original ANIMATE_CLASS,
            so I'm leaving everything as is

            case ckidAVIMAINHDR:
              ...

                if (prle->pMainHeader->dwInitialFrames != 0)
                    goto exit;

                if (prle->pMainHeader->dwStreams > 2)
                    goto exit;
          }

          if AviHeader.dwInitialFrames <> 0 then Exit;
          if AviHeader.dwStreams > 2 then Exit;

          AviHeaderPresent := True;
          FAvi.FrameRateMs := AviHeader.dwMicroSecPerFrame div 1000;
          if FAvi.FrameRateMs = 0 then
            FAvi.FrameRateMs := FDefaultRateMs;
          if Chunk.Size > SizeOf(AviHeader) then
            Stream.Seek(Chunk.Size - SizeOf(AviHeader), soFromCurrent);
          if Chunk.Size mod 2 = 1 then
            Stream.Seek(1, soFromCurrent);
        end;
        2: // Stream Header
        begin
          if not StrfPresent then
          begin
            Stream.ReadBuffer(ListType, SizeOf(TFourCC));
            IsVideoStream := (ListType = streamtypeVIDEO);
            if Chunk.Size > SizeOf(TFourCC) then
              Stream.Seek(Chunk.Size - SizeOf(TFourCC), soFromCurrent);
          end
          else
            Stream.Seek(Chunk.Size, soFromCurrent);
          if Chunk.Size mod 2 = 1 then
            Stream.Seek(1, soFromCurrent);
        end;
        3: // Stream Format
        begin
          if IsVideoStream and not StrfPresent then
          begin
            Stream.ReadBuffer(FAvi.Header, SizeOf(TBitmapInfoHeader));
            StrfPresent := True;
            FAvi.Width := FAvi.Header.biWidth;
            FAvi.Height := Abs(FAvi.Header.biHeight);
            FAvi.FullFrameSize := ((FAvi.Width * FAvi.Header.biBitCount + 31) and not 31) div 8 * FAvi.Height;
            PalCount := 0;
            PalBytesInChunk := Integer(Chunk.Size) - SizeOf(TBitmapInfoHeader);
            if FAvi.Header.biBitCount in [0..8] then
            begin
              if FAvi.Header.biClrUsed > 0 then
                PalCount := FAvi.Header.biClrUsed
              else
                PalCount := 1 shl FAvi.Header.biBitCount;
              if PalCount * SizeOf(TRGBQuad) > PalBytesInChunk then
                PalCount := PalBytesInChunk div SizeOf(TRGBQuad);
              if PalCount < 0 then
                PalCount := 0;
              SetLength(FAvi.Palette, PalCount);
              if PalCount > 0 then
                Stream.ReadBuffer(FAvi.Palette[0], PalCount * SizeOf(TRGBQuad));
            end;
            if PalBytesInChunk > PalCount * SizeOf(TRGBQuad) then
              Stream.Seek(PalBytesInChunk - PalCount * SizeOf(TRGBQuad), soFromCurrent);
            if Chunk.Size mod 2 = 1 then
              Stream.Seek(1, soFromCurrent);
          end
          else
            Stream.Seek(Chunk.Size + (Chunk.Size mod 2), soFromCurrent);
        end;
      else
        // cktypeDIBbits (db) or cktypeDIBcompressed (dc)
        if (Chunk.ID[2] = 'd') and ((Chunk.ID[3] = 'b') or (Chunk.ID[3] = 'c')) then
        begin
          SetLength(FrameData, Chunk.Size);
          if Chunk.Size > 0 then
            Stream.ReadBuffer(FrameData[0], Chunk.Size);

          FrameIdx := Length(FAvi.Frames);
          SetLength(FAvi.Frames, FrameIdx + 1);

          if FAvi.Header.biCompression = BI_RLE8 then
          begin
            if FrameIdx > 0 then
              FAvi.Frames[FrameIdx] := DecodeRLE8(FrameData, FAvi.Width, FAvi.Height, FAvi.Frames[FrameIdx - 1])
            else
              FAvi.Frames[FrameIdx] := DecodeRLE8(FrameData, FAvi.Width, FAvi.Height, nil);
          end
          else
            FAvi.Frames[FrameIdx] := FrameData;

          if Chunk.Size mod 2 = 1 then
            Stream.Seek(1, soFromCurrent);
        end
        else
          Stream.Seek(Chunk.Size + (Chunk.Size mod 2), soFromCurrent);
      end;
    end;
  end;

begin
  AviHeaderPresent := False;
  StrfPresent := False;
  IsVideoStream := False;
  FAvi.FrameRateMs := FDefaultRateMs;

  EndPos := Stream.Position + (RiffDataSize - SizeOf(TFourCC));
  WalkChunks(EndPos);

  if not AviHeaderPresent then
    raise EAnimateException.Create('There is no “avih” chunk in the stream');
  if not StrfPresent then
    raise EAnimateException.Create('Video stream format not found (strf)');
  if Length(FAvi.Frames) = 0 then
    raise EAnimateException.Create('No video frames were found in the AVI file (only uncompressed DIB and RLE8 are supported)');

  BuildAviBitmaps;
  AutoDetectTransparentColor;
  Result := pkAVI;
end;

procedure TCustomAniPaintBox.Paint;
begin
  Canvas.Brush.Color := Color;
  Canvas.FillRect(ClientRect);
  if not FLoaded then Exit;
  case FKind of
    pkAniCursor: PaintAniFrame;
    pkAVI: PaintAviFrame;
  end;
end;

procedure TCustomAniPaintBox.PaintAniFrame;
var
  IcoHandle: HICON;
  R: TRect;
  X, Y, IcoSize: Integer;
begin
  if Length(FAniCursorIcon.Seq) = 0 then Exit;
  IcoHandle := FAniCursorIcon.Icons[FAniCursorIcon.Seq[FFrameIdx]];
  if IcoHandle = 0 then Exit;

  R := ClientRect;
  case FStretchMode of
    asmCenter:
    begin
      IcoSize := 32;
      X := (R.Width - IcoSize) div 2;
      Y := (R.Height - IcoSize) div 2;
      PaintBackground(X, Y, IcoSize, IcoSize);
      DrawIconEx(Canvas.Handle, X, Y, IcoHandle, IcoSize, IcoSize, 0, 0, DI_NORMAL);
    end;
    asmStretch:
      DrawIconEx(Canvas.Handle, 0, 0, IcoHandle, R.Width, R.Height, 0, 0, DI_NORMAL);
  end;
end;

procedure TCustomAniPaintBox.PaintAviFrame;
var
  R: TRect;
  X, Y: Integer;
  MemDC: HDC;
  OldBmp: HBITMAP;
  AColor: COLORREF;
begin
  if Length(FAvi.Bitmaps) = 0 then Exit;
  if FAvi.Bitmaps[FFrameIdx] = 0 then Exit;

  R := ClientRect;
  MemDC := CreateCompatibleDC(Canvas.Handle);
  if MemDC = 0 then Exit;
  try
    OldBmp := SelectObject(MemDC, FAvi.Bitmaps[FFrameIdx]);
    try
      case FStretchMode of
        asmCenter:
        begin
          X := (R.Width - FAvi.Width) div 2;
          Y := (R.Height - FAvi.Height) div 2;
          PaintBackground(X, Y, FAvi.Width, FAvi.Height);
          if FBackgroundMode in [abmTransparent, abmGrayChecker] then
          begin
            AColor := ColorToRGB(FTransparentColor);
            TransparentBlt(Canvas.Handle, X, Y, FAvi.Width, FAvi.Height,
              MemDC, 0, 0, FAvi.Width, FAvi.Height, AColor);
          end
          else
            BitBlt(Canvas.Handle, X, Y, FAvi.Width, FAvi.Height,
              MemDC, 0, 0, SRCCOPY);
        end;
        asmStretch:
        begin
          if FBackgroundMode in [abmTransparent, abmGrayChecker] then
          begin
            AColor := ColorToRGB(FTransparentColor);
            TransparentBlt(Canvas.Handle, 0, 0, R.Width, R.Height,
              MemDC, 0, 0, FAvi.Width, FAvi.Height, AColor);
          end
          else
          begin
            SetStretchBltMode(Canvas.Handle, COLORONCOLOR);
            StretchBlt(Canvas.Handle, 0, 0, R.Width, R.Height,
              MemDC, 0, 0, FAvi.Width, FAvi.Height, SRCCOPY);
          end;
        end;
      end;
    finally
      SelectObject(MemDC, OldBmp);
    end;
  finally
    DeleteDC(MemDC);
  end;
end;

procedure TCustomAniPaintBox.PaintBackground(X, Y, W, H: Integer);
var
  AText: string;
begin
  if BackgroundMode = abmTransparent then Exit;
  FInvalidateRect := Bounds(X, Y, W, H);
  if BackgroundMode = abmFillColor then
  begin
    Canvas.Brush.Color := FillColor;
    Canvas.FillRect(FInvalidateRect);
    Exit;
  end;
  X := MulDiv(2, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
  InflateRect(FInvalidateRect, X, X);
  DrawCheckerBoard(MulDiv(6, FCurrentPPI, USER_DEFAULT_SCREEN_DPI), FInvalidateRect);
  if ShowInfo then
  begin
    AText := Format('%s %dx%d %d frames', [
      IfThen(FKind = pkAniCursor, 'ANICURSOR', 'AVI'), W, H,
      IfThen(FKind = pkAniCursor, Length(FAniCursorIcon.Seq), Length(FAvi.Frames))
      ]);
    Canvas.Font.Name := 'Segoe UI';
    Canvas.Font.Size := MulDiv(10, FCurrentPPI, USER_DEFAULT_SCREEN_DPI);
    Canvas.Brush.Style := bsClear;
    X := (ClientWidth - Canvas.TextWidth(AText)) div 2;
    Canvas.TextOut(X, Y + H + MulDiv(6, FCurrentPPI, USER_DEFAULT_SCREEN_DPI), AText);
  end;
end;

procedure TCustomAniPaintBox.PaintNewFrame(Sender: TObject);
var
  NewInterval: DWORD;
  FrameCount: Integer;
begin
  case FKind of
    pkAniCursor: FrameCount := Length(FAniCursorIcon.Seq);
    pkAVI: FrameCount := Length(FAvi.Frames);
  else
    FrameCount := 0;
  end;
  if FrameCount = 0 then Exit;

  Inc(FFrameIdx);
  if FFrameIdx >= FrameCount then
    FFrameIdx := 0;

  case FKind of
    pkAniCursor:
      begin
        if FFrameIdx < Length(FAniCursorIcon.Rate) then
          NewInterval := FAniCursorIcon.Rate[FFrameIdx]
        else
          NewInterval := FDefaultRateMs;
        if NewInterval = 0 then
          NewInterval := FDefaultRateMs;
      end;
    pkAVI:
      NewInterval := FAvi.FrameRateMs;
  else
    NewInterval := FDefaultRateMs;
  end;

  FFrameTimer.Interval := NewInterval;
  if FInvalidateRect.IsEmpty then
    Invalidate
  else
    if (Parent <> nil) and Parent.HandleAllocated then
      InvalidateRect(Parent.Handle, BoundsRect, False);
end;

procedure TCustomAniPaintBox.SetActive(Value: Boolean);
begin
  if Value then
    Play
  else
    Stop;
end;

procedure TCustomAniPaintBox.SetBackgroundMode(const Value: TAniBackgroundMode);
begin
  if BackgroundMode <> Value then
  begin
    FBackgroundMode := Value;
    Invalidate;
  end;
end;

procedure TCustomAniPaintBox.SetFillColor(const Value: TColor);
begin
  if FillColor <> Value then
  begin
    FFillColor := Value;
    if BackgroundMode = abmFillColor then
      Invalidate;
  end;
end;

procedure TCustomAniPaintBox.SetShowInfo(const Value: Boolean);
begin
  if ShowInfo <> Value then
  begin
    FShowInfo := Value;
    Invalidate;
  end;
end;

procedure TCustomAniPaintBox.SetStretchMode(Value: TAniStretchMode);
begin
  if FStretchMode <> Value then
  begin
    FStretchMode := Value;
    Invalidate;
  end;
end;

procedure TCustomAniPaintBox.Play;
begin
  if not FLoaded then Exit;
  FInvalidateRect := TRect.Empty;
  FFrameTimer.Interval :=
    IfThen(FKind = pkAVI, FAvi.FrameRateMs, FDefaultRateMs);
  FActive := True;
  FFrameTimer.Enabled := True;
end;

procedure TCustomAniPaintBox.Stop;
begin
  FActive := False;
  FFrameTimer.Enabled := False;
end;

end.

