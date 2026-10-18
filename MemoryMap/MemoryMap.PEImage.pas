////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : MemoryMap.PEImage.pas
//  * Purpose   : The class collects data by sections and directories of a PE file
//  * Author    : Alexander (Rouse_) Bagel
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.4.41
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : https://github.com/AlexanderBagel/ProcessMemoryMap/releases
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//  *
//  * SPDX-License-Identifier: MPL-2.0
//  * This Source Code Form is subject to the terms of the Mozilla Public
//  * License, v. 2.0. If a copy of the MPL was not distributed with this
//  * file, You can obtain one at http://mozilla.org/MPL/2.0/.
//  *
//  ****************************************************************************
//  *
//  * Support the Project:
//  *
//  * If you found this project useful, you can support its development
//  * on the author's main-project page:
//  *
//  * https://boosty.to/processmemorymap
//  *
//  ****************************************************************************
//

unit MemoryMap.PEImage;

interface

uses
  Winapi.Windows,
  Generics.Collections,
  MemoryMap.Utils,
  MemoryMap.ImageHlp,
  SysUtils;

type
  TSection = record
    Caption: ShortString;
    Address: NativeUInt;
    Size: NativeUInt;
    IsCode: Boolean;
    IsData: Boolean;
  end;

  TDirectoryFlag = (dfDirectory, dfEntryPoint, dfTlsCallback);

  TDirectory = record
    Flag: TDirectoryFlag;
    Caption: ShortString;
    Address: ULONG_PTR;
    Size: NativeUInt;
  end;

  TDirectoryArray = record
    Count: Integer;
    Data: array [0..14] of TDirectory;
  end;

  TTLSCallback = record
    Caption: ShortString;
    Address: Pointer;
  end;

  TCoffSymbol = packed record
    Name: array [0..3] of Byte;
    StrOfs: LongInt;
    Value: LongInt;
    Section: SmallInt;
    Empty: Word;
    Typ: Byte;
    Aux: Byte;
  end;

  TPEImage = class
  private
    FProcessHandle: THandle;
    FImage64: Boolean;
    FImageBase: Pointer;
    FImageInfo: LOADED_IMAGE;
    FSections: TList<TSection>;
    FDirectoryes: TList<TDirectoryArray>;
    FEntryPoints: TList<Pointer>;
    FTLSCallbacks: TList<TTLSCallback>;
  protected
    procedure EnumSections;
    procedure EnumDirectories(LoadAsImage: Boolean);
  public
    constructor Create(AProcessHandle: THandle);
    destructor Destroy; override;
    procedure GetInfoFromImage(const FileName: string; ImageBase: Pointer;
      FirstSectionSize: NativeUInt; LoadAsImage: Boolean = True);
    function GetSectionArAddr(Value: Pointer): TSection;
    property Sections: TList<TSection> read FSections;
    property Directoryes: TList<TDirectoryArray> read FDirectoryes;
    property EntryPoints: TList<Pointer> read FEntryPoints;
    property TLSCallbacks: TList<TTLSCallback> read FTLSCallbacks;
  end;

implementation

{ TPEImage }

constructor TPEImage.Create(AProcessHandle: THandle);
begin
  FProcessHandle := AProcessHandle;
  FSections := TList<TSection>.Create;
  FDirectoryes := TList<TDirectoryArray>.Create;
  FEntryPoints := TList<Pointer>.Create;
  FTLSCallbacks := TList<TTLSCallback>.Create;
end;

destructor TPEImage.Destroy;
begin
  FTLSCallbacks.Free;
  FEntryPoints.Free;
  FDirectoryes.Free;
  FSections.Free;
  inherited;
end;

procedure TPEImage.EnumDirectories(LoadAsImage: Boolean);
type
  PLSTable32 = ^TLSTable32;
  TLSTable32 = record
    StartAddressOfRawData,
    EndAddressOfRawData,
    AddressOfIndex,
    AddressOfCallBacks: UInt32;
  end;

  PLSTable64 = ^TLSTable64;
  TLSTable64 = record
    StartAddressOfRawData,
    EndAddressOfRawData,
    AddressOfIndex,
    AddressOfCallBacks: UInt64;
  end;

const
  DirectoryStr: array [0..14] of string =
    ('export', 'import', 'resource', 'exception',
    'security', 'basereloc', 'debug', 'copyright',
    'globalptr', 'tls', 'load_config', 'bound_import',
    'iat', 'delay_import', 'com');
var
  I, A: Integer;
  dwDirSize: DWORD;
  DirAddr: Pointer;
  Directory: TDirectoryArray;
  pTLSCursor: PULONG_PTR;
  pTLSTable: array [0..SizeOf(TLSTable64) - 1] of Byte;
  NumberOfBytesWritten: SIZE_T;
  TLSCallbackTable: array of Byte;
  TLSCallbackTableCursor: Byte;
  pCallBack: Pointer;
  CallbackData: TTLSCallback;

  function GetNextCallback: Pointer;
  begin
    if FImage64 then
    begin
      Result := Pointer(PUint64(@TLSCallbackTable[TLSCallbackTableCursor])^);
      Inc(TLSCallbackTableCursor, 8);
    end
    else
    begin
      Result := Pointer(PDWORD(@TLSCallbackTable[TLSCallbackTableCursor])^);
      Inc(TLSCallbackTableCursor, 4);
    end;
  end;

begin
  ZeroMemory(@Directory, SizeOf(TDirectoryArray));
  Directory.Count := 0;
  for I := 0 to 14 do
  begin
    DirAddr := ImageDirectoryEntryToData(FImageInfo.MappedAddress,
      True, I, dwDirSize);
    if DirAddr <> nil then
    begin
      Inc(Directory.Count);
      Directory.Data[I].Flag := dfDirectory;
      Directory.Data[I].Caption := ShortString(DirectoryStr[I]);
      Directory.Data[I].Address := NativeUint(FImageBase) +
        NativeUint(DirAddr) - NativeUint(FImageInfo.MappedAddress);
      Directory.Data[I].Size := dwDirSize;

      if I = IMAGE_DIRECTORY_ENTRY_TLS then
      begin
        pTLSCursor := PULONG_PTR(NativeUint(FImageBase) +
          NativeUint(DirAddr) - NativeUint(FImageInfo.MappedAddress));

        if not ReadProcessMemory(FProcessHandle, pTLSCursor,
          @pTLSTable[0], SizeOf(pTLSTable), NumberOfBytesWritten) then Continue;

        SetLength(TLSCallbackTable, 256);
        if FImage64 then
          pTLSCursor := Pointer(PLSTable64(@pTLSTable[0])^.AddressOfCallBacks)
        else
          pTLSCursor := Pointer(PLSTable32(@pTLSTable[0])^.AddressOfCallBacks);

        if (ULONG_PTR(pTLSCursor) < ULONG_PTR(FImageBase)) or
          (ULONG_PTR(pTLSCursor) > (ULONG_PTR(FImageBase) + FImageInfo.SizeOfImage)) then
          Continue;

        if not LoadAsImage then Exit;

        if not ReadProcessMemory(FProcessHandle,
          pTLSCursor, @TLSCallbackTable[0], Length(TLSCallbackTable),
          NumberOfBytesWritten) then Continue;

        A := 0;
        TLSCallbackTableCursor := 0;
        pCallBack := GetNextCallback;
        while pCallBack <> nil do
        begin
          CallbackData.Caption := ShortString('TLS Callback ' + IntToStr(A));
          CallbackData.Address := pCallBack;
          TLSCallbacks.Add(CallbackData);
          Inc(A);
          if A > 31 then // 32 callbacks? Seriously?!!!
            Break;
          pCallBack := GetNextCallback;
        end;
      end;
    end;
  end;
  FDirectoryes.Add(Directory);
end;

procedure TPEImage.EnumSections;
var
  ImageSectionHeader: PImageSectionHeader;
  I, Index: Integer;
  Section: TSection;
  COFFOffset, SectionNameOffset: NativeUInt;
  SectionName: array [0..255] of AnsiChar;
begin
  ImageSectionHeader := FImageInfo.Sections;
  COFFOffset := FImageInfo.FileHeader.FileHeader.PointerToSymbolTable +
    FImageInfo.FileHeader.FileHeader.NumberOfSymbols * SizeOf(TCoffSymbol);
  for I := 0 to Integer(FImageInfo.NumberOfSections) - 1 do
  begin
    Section.Caption := Copy(ShortString(
      PAnsiChar(@ImageSectionHeader^.Name[0])), 1, IMAGE_SIZEOF_SHORT_NAME);

    if (COFFOffset <> 0) and (Section.Caption[1] = '/') then
    begin
      if TryStrToInt(Copy(string(Section.Caption), 2, 7), Index) then
      begin
        SectionNameOffset := COFFOffset + NativeUInt(Index);
        SectionNameOffset := SectionNameOffset + NativeUint(FImageInfo.MappedAddress);
        SectionName[255] := #0;
        CopyMemory(@SectionName[0], Pointer(SectionNameOffset), 255);
        Section.Caption := ShortString(PAnsiChar(@SectionName[0]));
      end;
    end;

    Section.Address := NativeUint(FImageBase) + ImageSectionHeader^.VirtualAddress;
    Section.Size := AlignedSectionSize(FImageInfo, ImageSectionHeader^.SizeOfRawData);
    Section.IsCode := IsExecute(ImageSectionHeader^.Characteristics);
    Section.IsData := IsWrite(ImageSectionHeader^.Characteristics);
    FSections.Add(Section);
    Inc(ImageSectionHeader);
  end;
end;

procedure TPEImage.GetInfoFromImage(const FileName: string; ImageBase: Pointer;
  FirstSectionSize: NativeUInt; LoadAsImage: Boolean);
var
  Section: TSection;
begin
  FImageBase := ImageBase;
  if MapAndLoad(PAnsiChar(AnsiString(FileName)), nil, @FImageInfo, True, True) then
  try
    FImage64 := FImageInfo.FileHeader^.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    Section.Caption := 'PEHeader';
    Section.Address := NativeUint(ImageBase);
    Section.Size := FirstSectionSize;
    Section.IsCode := False;
    Section.IsData := False;
    FSections.Add(Section);
    if FImageInfo.FileHeader.OptionalHeader.AddressOfEntryPoint <> 0 then
      FEntryPoints.Add(Pointer(NativeUInt(ImageBase) +
        FImageInfo.FileHeader.OptionalHeader.AddressOfEntryPoint));
    EnumSections;
    if FProcessHandle <> 0 then
      EnumDirectories(LoadAsImage);
  finally
    UnMapAndLoad(@FImageInfo);
  end;
end;

function TPEImage.GetSectionArAddr(Value: Pointer): TSection;
var
  I: TSection;
begin
  ZeroMemory(@Result, SizeOf(TSection));
  for I in FSections do
    if I.Address <= NativeUInt(Value) then
      if I.Address + I.Size > NativeUInt(Value) then
        Exit(I);
end;

end.
