////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uPluginManager.pas
//  * Purpose   : Менеджер плагинов
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.3.25
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uPluginManager;

interface

uses
  Windows,
  Classes,
  SysUtils,
  Generics.Collections,
  pmm_plugin,
  MemoryMap.Core,
  RawScanner.Core,
  RawScanner.Types,
  RawScanner.SymbolStorage;

type
  TDescriptorData = record
    NameSpace,
    Caption,
    Description: string;
    Size: DWORD;
  end;

  TPluginManager = class
  strict private
    class var FInstance: TPluginManager;
    class destructor ClassDestroy;
  private type
    TPluginInstance = record
      Handle: THandle;
      UID: DWORD;
      Name, Author, Page, Description: string;
      Gate: TPluginCallGate;
    end;
  private
    FList: TList<TPluginInstance>;
    FIndex: TDictionary<THandle, Integer>;
    FProgress: TProgressEvent;
    procedure DoProgress(const Step: string; APecent: Integer);
    procedure Init;
    procedure Release;
  public
    constructor Create;
    destructor Destroy; override;
    class function GetInstance: TPluginManager;
    procedure OpenProcess(PID: Cardinal);
    procedure CloseProcess;
    function GetGetDescriptorData(PluginHandle, DescriptorHandle: THandle;
      var Data: TDescriptorData): Boolean;
    property Items: TList<TPluginInstance> read FList;
    property OnProgress: TProgressEvent read FProgress write FProgress;
  end;

  function PluginManager: TPluginManager;

implementation

function PluginManager: TPluginManager;
begin
  Result := TPluginManager.GetInstance;
end;

{ TPluginManager }

class destructor TPluginManager.ClassDestroy;
begin
  FreeAndNil(FInstance);
end;

procedure TPluginManager.CloseProcess;
begin
  for var I := 0 to FList.Count - 1 do
    if Assigned(FList.List[I].Gate.Close) then
      FList.List[I].Gate.Close;
end;

constructor TPluginManager.Create;
begin
  FList := TList<TPluginInstance>.Create;
  FIndex := TDictionary<THandle, Integer>.Create;
  Init;
end;

destructor TPluginManager.Destroy;
begin
  Release;
  FList.Free;
  FIndex.Free;
  inherited;
end;

procedure TPluginManager.DoProgress(const Step: string; APecent: Integer);
begin
  if Assigned(FProgress) then
    FProgress(Step, APecent);
end;

function TPluginManager.GetGetDescriptorData(PluginHandle,
  DescriptorHandle: THandle; var Data: TDescriptorData): Boolean;
var
  Index: Integer;
  DescData: PDescriptorData;
  Size: Integer;
begin
  Result := FIndex.TryGetValue(PluginHandle, Index);
  if not Result then Exit;
  Size := 0;
  Result :=
    FList[Index].Gate.GetDescriptorData(
      DescriptorHandle, nil, @Size) = ERROR_INSUFFICIENT_BUFFER;
  if not Result then Exit;
  GetMem(DescData, Size);
  try
    Result := FList[Index].Gate.GetDescriptorData(
      DescriptorHandle, DescData, @Size) = NO_ERROR;
    if Result then
    begin
      Data.NameSpace := DescData.NameSpace;
      Data.Caption := DescData.Caption;
      Data.Description := DescData.Description;
      Data.Size := DescData.Size;
    end;
  finally
    FreeMem(DescData);
  end;
end;

class function TPluginManager.GetInstance: TPluginManager;
begin
  if FInstance = nil then
    FInstance := TPluginManager.Create;
  Result := FInstance;
end;

procedure TPluginManager.Init;

  function Is64Image(const FilePath: string; out ImageIs64: Boolean): Boolean;
  var
    F: TBufferedFileStream;
    IDH: TImageDosHeader;
    NT: TImageNtHeaders;
  begin
    Result := False;
    ImageIs64 := False;
    F := TBufferedFileStream.Create(FilePath, 4096);
    try
      if F.Read(IDH, SizeOf(IDH)) <> SizeOf(IDH) then Exit;
      if IDH.e_magic <> IMAGE_DOS_SIGNATURE then Exit;
      F.Position := IDH._lfanew;
      if F.Read(NT, SizeOf(NT)) <> SizeOf(NT) then Exit;
      Result := NT.Signature = IMAGE_NT_SIGNATURE;
      if Result then
        ImageIs64 := NT.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    finally
      F.Free;
    end;
  end;

var
  PluginDir: string;
  SR: TSearchRec;
  Inst: TPluginInstance;
  InitProc: Tpmm_get_plugin_info;
  PluginData: TPlugin;
  ImageIs64: Boolean;
begin
  {$IFDEF DEBUG}
  PluginDir := ExtractFilePath(ParamStr(0)) + '..\..\plugins\';
  {$ELSE}
  PluginDir := ExtractFilePath(ParamStr(0)) + 'plugins\';
  {$ENDIF}
  if FindFirst(PluginDir + '*.dll', faAnyFile, SR) = 0 then
  try
    repeat
      if not Is64Image(PluginDir + SR.Name, ImageIs64) then Continue;
      {$IFDEF WIN32}
      if ImageIs64 then Continue;
      {$ELSE}
      if not ImageIs64 then Continue;
      {$ENDIF}
      Inst.Handle := LoadLibrary(PChar(PluginDir + SR.Name));
      if Inst.Handle <= HINSTANCE_ERROR then
        Continue;
      InitProc := GetProcAddress(Inst.Handle, PMM_PLUGIN_ENTRYPOINT_NAME);
      if Assigned(InitProc) then
      begin
        PluginData := InitProc;
        // проверка инициализации UID по которому будут отключаться плагины
        if PluginData.PluginUID = 0 then Continue;
        // проверка инициализации обязательных функций
        if not (
          Assigned(PluginData.Gate.Open) and
          Assigned(PluginData.Gate.DescriptorCount) and
          Assigned(PluginData.Gate.GetDescriptor) and
          Assigned(PluginData.Gate.GetDescriptorData)) then
            Continue;
        Inst.UID := PluginData.PluginUID;
        Inst.Name := PluginData.PluginName;
        Inst.Author := PluginData.PluginAuthor;
        Inst.Page := PluginData.PluginHomePage;
        Inst.Description := PluginData.PluginDesсription;
        Inst.Gate := PluginData.Gate;
        FIndex.Add(Inst.Handle, FList.Add(Inst));
      end;
    until FindNext(SR) <> 0;
  finally
    FindClose(sr);
  end;
end;

procedure TPluginManager.OpenProcess(PID: Cardinal);
var
  InitBuff: array of Byte;

  function MakeInitBuff: Boolean;
  var
    Size, I: Integer;
    pCurrModule, pPrevModule: PProcessModule;
  begin
    Size := 0;
    // вычисление требуемого размера (+2 под нулевой юникодный чар)
    for I := 0 to MemoryMapCore.Modules.Count - 1 do
      Inc(Size, SizeOf(TProcessModule) +
        Length(MemoryMapCore.Modules[I].Path) shl 1 + 2);

    Result := Size > 0;
    if not Result then Exit;

    SetLength(InitBuff, Size);
    pPrevModule := nil;
    pCurrModule := @InitBuff[0];
    for var Item in MemoryMapCore.Modules do
    begin
      if Assigned(pPrevModule) then
        pPrevModule.FLink := pCurrModule;
      pCurrModule.BLink := pPrevModule;
      pPrevModule := pCurrModule;
      pCurrModule.Instance := Item.BaseAddr;
      pCurrModule.LoadAsDataFile := RawScannerCore.Modules.GetModule(Item.BaseAddr) < 0;
      pCurrModule.ImagePath := PWideChar(PByte(pCurrModule) + SizeOf(TProcessModule));
      Size := Length(Item.Path) shl 1;
      Move(Item.Path[1], pCurrModule.ImagePath^, Size);
      pCurrModule := PProcessModule(PByte(pCurrModule.ImagePath) + Size + 2);
    end;
  end;

var
  ExceptData: string;
  MaxCount, LastPercent, CurrentPercent: Integer;
  Symbol: TSymbolData;
  Descr: TDescriptor;
begin
  if not MakeInitBuff then
    Exit;
  Symbol.DataType := sdtPluginDescriptor;
  ExceptData := EmptyStr;
  ZeroMemory(@Descr, SizeOf(TDescriptor));
  for var Item in FList do
  try
    Symbol.Plugin.PluginHandle := Item.Handle;
    if Assigned(Item.Gate.Close) then
      Item.Gate.Close;
    if Item.Gate.Open(MemoryMapCore.PID, @InitBuff[0]) = NO_ERROR then
    begin
      MaxCount := Item.Gate.DescriptorCount;
      LastPercent := 0;
      for var I := 0 to MaxCount - 1 do
      begin
        CurrentPercent := Round(I / (MaxCount / 100));
        if CurrentPercent <> LastPercent then
        begin
          LastPercent := CurrentPercent;
          DoProgress(Format('Load plugin data "%s": %d%%',
            [Item.Name, CurrentPercent]), CurrentPercent);
        end;
        if Item.Gate.GetDescriptor(I, @Descr) = NO_ERROR then
        begin
          Symbol.AddrVA := Descr.AddrVA;
          Symbol.Plugin.DescriptorHandle := Descr.Handle;
          Symbol.Plugin.IsFunction := Descr.DescrType = PMM_DESCR_TYPE_FUNCTION;
          SymbolStorage.Add(Symbol);
        end;
      end;
    end;
  except
    on E: Exception do
    begin
      ExceptData := ExceptData + Trim(Item.Name + ' (') +
        IntToHex(Item.UID) + ') open error, ' +
        E.ClassName + ': ' + E.Message + sLineBreak;
    end;
  end;
  if ExceptData <> EmptyStr then
    MessageBox(0, PChar(ExceptData), 'Process Memory Map', MB_ICONERROR);
end;

procedure TPluginManager.Release;
begin
  for var I := 0 to FList.Count - 1 do
  begin
    if Assigned(FList[I].Gate.Close) then
      FList[I].Gate.Close;
    FreeLibrary(FList[I].Handle);
  end;
end;

end.
