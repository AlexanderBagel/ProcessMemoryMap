////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.SymbolStorage.pas
//  * Purpose   : Класс для хранения адресов всех известных RawScanner структур
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.0.11
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.SymbolStorage;

interface

  {$I rawscanner.inc}

uses
  Windows,
  SysUtils,
  Classes,
  Generics.Collections,
  Generics.Defaults,
  RawScanner.Types;

type
  TSymbolDataType = (
    sdtNone,
    // типы адресов полученые от таблиц загрузчика
    sdtLdrData32, sdtLdrEntry32, sdtLdrData64, sdtLdrEntry64,

    // типы адресов полученые от таблиц контекста активации
    sdtCtxProcess, sdtCtxSystem, sdtCtxToc, sdtCtxTocEntry,
    sdtCtxExtToc, sdtCtxExtTocEntry, sdtCtxAssemblyRoster,
    sdtCtxAssemblyRosterEntry, sdtCtxStrSecHeader, sdtCtxStrSecEntry,
    sdtCtxStrSecEntryData,

    // отдельный тип под плагины
    sdtPluginDescriptor,

    // типы адресов использующие Binary (заполняются в ModulesData)
    sdtBinaryFirst,

    sdtInstance, sdtExport, sdtEntryPoint,
    sdtUString, sdtAString, // <<< строки только для дизассемблера, в Raw не выводятся
    // табличные данные экспорта
    sdtEATAddr, sdtEATName, sdtEATOrdinal,
    // табличные данные импорта
    sdtImportTable, sdtImportTable64, sdtImportNameTable, sdtImportNameTable64,
    sdtDelayedImportTable, sdtDelayedImportTable64,
    sdtDelayedImportNameTable, sdtDelayedImportNameTable64,
    // табличные данные TLS каллбэков
    sdtTlsCallback32, sdtTlsCallback64,

    // структуры известные ModulesData
    sdtExportDir, sdtImportDescriptor, sdtDelayedImportDescriptor,
    sdtLoadConfig32, sdtLoadConfig64,
    sdtTLSDir32, sdtTLSDir64,

    sdtBinaryLast,

    // структуры ApiSet редиректора
    sdtApiSetNS, sdtApiSetNSEntry, sdtApiSetValueEntry,
    sdtApiSetRedirection, sdtApiSetHashEntry
    );

  TContextData = record
  case TSymbolDataType of
    sdtCtxProcess: (TotalSize: DWORD);
    sdtCtxAssemblyRosterEntry: (ContextVA: ULONG_PTR64; TokID: Integer);
  end;

  TModuleKey = record
    DelayedNameEmpty: Boolean;
    ModuleIndex: Word;
    ListIndex: Integer;
  end;

  TPluginData = record
    PluginHandle,
    DescriptorHandle: THandle;
    IsFunction: Boolean;
  end;

  TApiSetData = record
    Version: Integer;
    OriginalVA,               // адрес с которого читались реальные данные
    RemoteVA: ULONG_PTR64;    // адрес по которому нужно пересчитать оффсеты
    case TSymbolDataType of
      sdtApiSetNS: (NameSpaceSize: Integer);
  end;

  TSymbolData = record
    AddrVA: ULONG_PTR64;
    DataType: TSymbolDataType;
    case TSymbolDataType of
      sdtCtxProcess: (Ctx: TContextData);
      sdtPluginDescriptor: (Plugin: TPluginData);
      sdtExport: (Binary: TModuleKey);
      sdtApiSetNS: (ApiSet: TApiSetData);
  end;

  TSymbolType = (stExport, stExportExactMatch, stAll);

  TRawScannerSymbolStorage = class
  strict private
    class var FInstance: TRawScannerSymbolStorage;
    class destructor ClassDestroy;
  private
    FActive: Boolean;
    FItems, FAddrList: TList<TSymbolData>;
    FItemIndex: TDictionary<ULONG_PTR64, Integer>;
    FStringsCount: Integer;
  public
    constructor Create; virtual;
    destructor Destroy; override;
    class function GetInstance: TRawScannerSymbolStorage;
    procedure Add(Value: TSymbolData);
    procedure Clear;
    function Count: Integer;
    procedure PrepareForWork;
    function GetDataTypeAtAddr(AddrVA: ULONG_PTR64): TSymbolDataType;
    function GetDataAtAddr(AddrVA: ULONG_PTR64; var Data: TSymbolData): Boolean;
    function GetExportAtAddr(AddrVA: ULONG_PTR64; AType: TSymbolType;
      var Data: TSymbolData): Boolean;
    function GetKnownAddrList(AddrVA: ULONG_PTR64; Size: Cardinal): TList<TSymbolData>;
    function UniqueCount: Integer;
    property Active: Boolean read FActive;
    property StringsCount: Integer read FStringsCount;
  end;

  function SymbolStorage: TRawScannerSymbolStorage;

  function MakeItem(AddrVA: ULONG_PTR64;
    DataType: TSymbolDataType): TSymbolData;

implementation

function SymbolStorage: TRawScannerSymbolStorage;
begin
  Result := TRawScannerSymbolStorage.GetInstance;
end;

function MakeItem(AddrVA: ULONG_PTR64;
  DataType: TSymbolDataType): TSymbolData;
begin
  Result.AddrVA := AddrVA;
  Result.DataType := DataType;
end;

{ TRawScannerSymbolStorage }

procedure TRawScannerSymbolStorage.Add(Value: TSymbolData);
begin
  FActive := False;
  FItems.Add(Value);
  if Value.DataType in [sdtAString, sdtUString] then
    Inc(FStringsCount);
end;

class destructor TRawScannerSymbolStorage.ClassDestroy;
begin
  FreeAndNil(FInstance);
end;

procedure TRawScannerSymbolStorage.Clear;
begin
  FItems.Clear;
  FAddrList.Clear;
  FItemIndex.Clear;
  FActive := False;
  FStringsCount := 0;
end;

function TRawScannerSymbolStorage.Count: Integer;
begin
  Result := FItems.Count;
end;

constructor TRawScannerSymbolStorage.Create;
begin
  FItems := TList<TSymbolData>.Create;
  FAddrList := TList<TSymbolData>.Create;
  FItemIndex := TDictionary<ULONG_PTR64, Integer>.Create;
end;

destructor TRawScannerSymbolStorage.Destroy;
begin
  FItemIndex.Free;
  FAddrList.Free;
  FItems.Free;
  inherited;
end;

function TRawScannerSymbolStorage.GetDataAtAddr(AddrVA: ULONG_PTR64;
  var Data: TSymbolData): Boolean;
var
  Index: Integer;
begin
  Result := FItemIndex.TryGetValue(AddrVA, Index);
  if Result then
    Data := FItems.List[Index];
end;

function TRawScannerSymbolStorage.GetDataTypeAtAddr(
  AddrVA: ULONG_PTR64): TSymbolDataType;
var
  Index: Integer;
begin
  if FItemIndex.TryGetValue(AddrVA, Index) then
    Result := FItems.List[Index].DataType
  else
    Result := sdtNone;
end;

function TRawScannerSymbolStorage.GetExportAtAddr(AddrVA: ULONG_PTR64;
  AType: TSymbolType; var Data: TSymbolData): Boolean;
var
  I, Index: Integer;
  MinLimit: ULONG_PTR64;
  Item: TSymbolData;
begin
  Result := FItemIndex.TryGetValue(AddrVA, Index);
  if Result then
  begin
    Data := FItems.List[Index];
    if AType <> stAll then
      Result := Data.DataType in [sdtExport, sdtEntryPoint];
    if Result then
      Exit;
    Result := (Data.DataType = sdtPluginDescriptor) and (Data.Plugin.IsFunction);
    if Result then
      Exit;
  end;
  if AType <> stExport then Exit;
  MinLimit := (AddrVA - $1000) and not $FFF;
  Index := -1;
  for I := FItems.Count - 1 downto 0 do
  begin
    Item := FItems.List[I];
    if (Item.AddrVA >= MinLimit) and (Item.AddrVA < AddrVA) and
      (Item.DataType in [sdtExport, sdtEntryPoint]) then
    begin
      Data := Item;
      Result := True;
      Break;
    end;
  end;
end;

class function TRawScannerSymbolStorage.GetInstance: TRawScannerSymbolStorage;
begin
  if FInstance = nil then
    FInstance := TRawScannerSymbolStorage.Create;
  Result := FInstance;
end;

function TRawScannerSymbolStorage.GetKnownAddrList(AddrVA: ULONG_PTR64;
  Size: Cardinal): TList<TSymbolData>;
var
  I, Index: Integer;
  MaxLimit: ULONG_PTR64;
  Item: TSymbolData;
begin
  Result := FAddrList;
  FAddrList.Clear;
  MaxLimit := AddrVA + Size;

  if not FItemIndex.TryGetValue(AddrVA, Index) then
  begin
    Index := -1;
    for I := 0 to FItems.Count - 1 do
    begin
      Item := FItems.List[I];
      if (Item.AddrVA >= AddrVA) and (Item.AddrVA < MaxLimit) then
      begin
        Index := I;
        Break;
      end;
    end;
  end;

  if Index < 0 then Exit;

  for I := Index to FItems.Count - 1 do
  begin
    Item := FItems.List[I];
    if (Item.AddrVA >= AddrVA) and (Item.AddrVA < MaxLimit) then
      FAddrList.Add(Item);
  end;
end;

procedure TRawScannerSymbolStorage.PrepareForWork;
begin
  FItems.Sort(TComparer<TSymbolData>.Construct(
    function (const L, R: TSymbolData): Integer
    begin
      if L.AddrVA = R.AddrVA then
        Result := 0
      else
        if L.AddrVA < R.AddrVA then
          Result := -1
        else
          Result := 1;
    end));
  FItemIndex.Clear;
  for var I := 0 to FItems.Count - 1 do
    FItemIndex.TryAdd(FItems.List[I].AddrVA, I);
  FActive := FItemIndex.Count > 0;;
end;

function TRawScannerSymbolStorage.UniqueCount: Integer;
begin
  Result := FItemIndex.Count;
end;

end.
