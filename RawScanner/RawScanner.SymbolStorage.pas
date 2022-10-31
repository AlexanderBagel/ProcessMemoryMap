////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.SymbolStorage.pas
//  * Purpose   : Класс для хранения адресов всех известных RawScanner структур
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2022.
//  * Version   : 1.0
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.SymbolStorage;

interface

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
    // эскпорт
    sdtExport
    );

  TContextData = record
  case TSymbolDataType of
    sdtCtxProcess: (TotalSize: DWORD);
    sdtCtxAssemblyRosterEntry: (ContextVA: ULONG_PTR64);
  end;

  TSymbolData = record
    AddrVA: ULONG_PTR64;
    DataType: TSymbolDataType;
    case TSymbolDataType of
      sdtCtxProcess: (Ctx: TContextData);
      sdtExport: (FuncIndex: Integer);
  end;

  TRawScannerSymbolStorage = class
  strict private
    class var FInstance: TRawScannerSymbolStorage;
    class destructor ClassDestroy;
  private
    FActive: Boolean;
    FItems, FAddrList: TList<TSymbolData>;
    FItemIndex: TDictionary<ULONG_PTR64, Integer>;
    FExport: TStringList;
  public
    constructor Create; virtual;
    destructor Destroy; override;
    class function GetInstance: TRawScannerSymbolStorage;
    procedure Add(Value: TSymbolData);
    procedure AddExport(AddrVA: ULONG_PTR64; const FuncName: string);
    procedure Clear;
    procedure PrepareForWork;
    function GetExportAtAddr(AddrVA: ULONG_PTR64): string;
    function GetDataTypeAtAddr(AddrVA: ULONG_PTR64): TSymbolDataType;
    function GetDataAtAddr(AddrVA: ULONG_PTR64; var Data: TSymbolData): Boolean;
    function GetKnownAddrList(AddrVA: ULONG_PTR64; Size: Cardinal): TList<TSymbolData>;
    property Active: Boolean read FActive;
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
end;

procedure TRawScannerSymbolStorage.AddExport(AddrVA: ULONG_PTR64;
  const FuncName: string);
var
  Value: TSymbolData;
begin
  Value.AddrVA := AddrVA;
  Value.DataType := sdtExport;
  Value.FuncIndex := FExport.Add(FuncName);
  Add(Value);
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
end;

constructor TRawScannerSymbolStorage.Create;
begin
  FItems := TList<TSymbolData>.Create;
  FAddrList := TList<TSymbolData>.Create;
  FItemIndex := TDictionary<ULONG_PTR64, Integer>.Create;
  FExport := TStringList.Create;
end;

destructor TRawScannerSymbolStorage.Destroy;
begin
  FExport.Free;
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

function TRawScannerSymbolStorage.GetExportAtAddr(AddrVA: ULONG_PTR64): string;
var
  Index: Integer;
begin
  if FItemIndex.TryGetValue(AddrVA, Index) and
    (FItems.List[Index].DataType = sdtExport) then
    Result := FExport[FItems.List[Index].FuncIndex]
  else
    Result := EmptyStr;
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

end.
