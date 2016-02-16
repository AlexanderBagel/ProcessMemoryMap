////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : MemoryMap
//  * Unit Name : MemoryMap.PEImage.pas
//  * Purpose   : Класс собирает данные по секциям и директориям PE файла
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2016.
//  * Version   : 1.0.3
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit MemoryMap.PEImage;

interface

uses
  Winapi.Windows,
  Generics.Collections,
  MemoryMap.Utils,
  Winapi.ImageHlp,
  SysUtils;

type
  TSection = record
    Caption: ShortString;
    Address: NativeUInt;
    Size: NativeUInt;
    IsCode: Boolean;
    IsData: Boolean;
  end;

  TDirectory = record
    Caption: ShortString;
    Address: NativeUInt;
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

  TPEImage = class
  private
    FProcessHandle: THandle;
    FProcess64: Boolean;
    FImageBase: Pointer;
    FImageInfo: LOADED_IMAGE;
    FSections: TList<TSection>;
    FDirectoryes: TList<TDirectoryArray>;
    FEntryPoints: TList<Pointer>;
    FTLSCallbacks: TList<TTLSCallback>;
  protected
    procedure EnumSections;
    procedure EnumDirectoryes;
  public
    constructor Create(AProcessHandle: THandle; AProcess64: Boolean);
    destructor Destroy; override;
    procedure GetInfoFromImage(const FileName: string; ImageBase: Pointer;
      FirstSectionSize: NativeUInt);
    function GetSectionArAddr(Value: Pointer): TSection;
    property Sections: TList<TSection> read FSections;
    property Directoryes: TList<TDirectoryArray> read FDirectoryes;
    property EntryPoints: TList<Pointer> read FEntryPoints;
    property TLSCallbacks: TList<TTLSCallback> read FTLSCallbacks;
  end;

implementation

{ TPEImage }

constructor TPEImage.Create(AProcessHandle: THandle; AProcess64: Boolean);
begin
  FProcessHandle := AProcessHandle;
  FProcess64 := AProcess64;
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

procedure TPEImage.EnumDirectoryes;
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

  // это все для работы с калбэками
  pTLSCursor: PULONG_PTR;
  pTLSTable: array [0..SizeOf(TLSTable64) - 1] of Byte;
  NumberOfBytesWritten: SIZE_T;
  TLSCallbackTable: array of Byte;
  TLSCallbackTableCursor: Byte;
  pCallBack: Pointer;
  CallbackData: TTLSCallback;

  function GetNextCallback: Pointer;
  begin
    if FProcess64 then
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
    // Получаем адрес директории
    DirAddr := ImageDirectoryEntryToData(FImageInfo.MappedAddress,
      True, I, dwDirSize);
    if DirAddr <> nil then
    begin
      Inc(Directory.Count);
      Directory.Data[I].Caption := ShortString(DirectoryStr[I]);
      Directory.Data[I].Address := NativeUint(FImageBase) +
        NativeUint(DirAddr) - NativeUint(FImageInfo.MappedAddress);
      Directory.Data[I].Size := dwDirSize;
      // дополнительно рассчитываем адреса всех TLS Callback
      if I = IMAGE_DIRECTORY_ENTRY_TLS then
      begin
        // рассчитываем адрес TLS таблицы у удаленном АП
        pTLSCursor := PULONG_PTR(NativeUint(FImageBase) +
          NativeUint(DirAddr) - NativeUint(FImageInfo.MappedAddress));
        // читаем начало TLS таблицы
        if not ReadProcessMemory(FProcessHandle, pTLSCursor,
          @pTLSTable[0], SizeOf(pTLSTable), NumberOfBytesWritten) then Continue;

        // читаем саму таблицу каллбэков
        SetLength(TLSCallbackTable, 256);
        if FProcess64 then
          pTLSCursor := Pointer(PLSTable64(@pTLSTable[0])^.AddressOfCallBacks)
        else
          pTLSCursor := Pointer(PLSTable32(@pTLSTable[0])^.AddressOfCallBacks);
        if not ReadProcessMemory(FProcessHandle,
          pTLSCursor, @TLSCallbackTable[0], Length(TLSCallbackTable),
          NumberOfBytesWritten) then Continue;

        // читаем их последовательно (по 4 или 8 байт в зависимости от битности)
        A := 0;
        TLSCallbackTableCursor := 0;
        pCallBack := GetNextCallback;
        while pCallBack <> nil do
        begin
          CallbackData.Caption := ShortString('TLS Callback ' + IntToStr(A));
          CallbackData.Address := pCallBack;
          TLSCallbacks.Add(CallbackData);
          Inc(A);
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
  I: Integer;
  Section: TSection;
begin
  ImageSectionHeader := FImageInfo.Sections;
  for I := 0 to Integer(FImageInfo.NumberOfSections) - 1 do
  begin
    Section.Caption := ShortString(PAnsiChar(@ImageSectionHeader^.Name[0]));
    Section.Address := NativeUint(FImageBase) + ImageSectionHeader^.VirtualAddress;
    Section.Size := AlignedSectionSize(FImageInfo, ImageSectionHeader^.SizeOfRawData);
    Section.IsCode := IsExecute(ImageSectionHeader^.Characteristics);
    Section.IsData := IsWrite(ImageSectionHeader^.Characteristics);
    FSections.Add(Section);
    Inc(ImageSectionHeader);
  end;
end;

procedure TPEImage.GetInfoFromImage(const FileName: string; ImageBase: Pointer;
  FirstSectionSize: NativeUInt);
var
  Section: TSection;
begin
  FImageBase := ImageBase;
  if MapAndLoad(PAnsiChar(AnsiString(FileName)), nil, @FImageInfo, True, True) then
  try
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
    EnumDirectoryes;
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
