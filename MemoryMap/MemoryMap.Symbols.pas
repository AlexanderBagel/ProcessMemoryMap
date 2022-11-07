////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : MemoryMap
//  * Unit Name : MemoryMap.Symbols.pas
//  * Purpose   : Класс для работы с символами.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2022.
//  * Version   : 1.0.2
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit MemoryMap.Symbols;

interface

uses
  Winapi.Windows,
  MemoryMap.ImageHlp,
  System.Classes,
  System.SysUtils,
  Generics.Collections;

type
  TSymbols = class
  private
    FInited: Boolean;
    FProcess: THandle;
    FModuleName: string;
    FBaseAddress: ULONG_PTR;
    FData: TDictionary<Pointer, string>;
  public
    constructor Create(hProcess: THandle);
    destructor Destroy; override;
    procedure Init(BaseAddress: ULONG_PTR; const ModuleName: string);
    procedure Release;
    function GetDescriptionAtAddr(Address, BaseAddress: ULONG_PTR;
      const ModuleName: string): string; overload;
    function GetDescriptionAtAddr(Address: ULONG_PTR): string; overload;
    function GetDescriptionAtAddr2(Address, BaseAddress: ULONG_PTR;
      const ModuleName: string): string;
    procedure GetExportFuncList(const ModuleName: string;
      BaseAddress: ULONG_PTR; Value: TStringList);
    property BaseAddress: ULONG_PTR read FBaseAddress;
  end;

implementation

const
  BuffSize = $7FF;

{ TSymbols }

constructor TSymbols.Create(hProcess: THandle);
begin
  FProcess := hProcess;
  SymSetOptions(SYMOPT_UNDNAME or SYMOPT_DEFERRED_LOADS);
  FInited := SymInitialize(hProcess, nil, True);
  FData := TDictionary<Pointer, string>.Create;
end;

destructor TSymbols.Destroy;
begin
  FData.Free;
  if FInited then
    SymCleanup(FProcess);
  inherited;
end;

function SymEnumsymbolsCallback(SymbolName: LPSTR; SymbolAddress: ULONG_PTR;
  SymbolSize: ULONG; UserContext: Pointer): Bool; stdcall;
var
  List: TStringList;
begin
  List := UserContext;
  List.AddObject(string(SymbolName), Pointer(SymbolAddress));
  Result := True;
end;

function TSymbols.GetDescriptionAtAddr(Address: ULONG_PTR): string;
begin
  Result := '';
  if FData.TryGetValue(Pointer(Address), Result) then
    Result := ExtractFileName(FModuleName) + '!' + Result;
end;

function TSymbols.GetDescriptionAtAddr2(Address, BaseAddress: ULONG_PTR;
  const ModuleName: string): string;
const
  SizeOfStruct = SizeOf(TImagehlpSymbol);
  MaxNameLength = BuffSize - SizeOfStruct;
var
  Symbol: PImagehlpSymbol;
  Displacement: NativeUInt;
begin
  Result := '';
  if not FInited then Exit;
  GetMem(Symbol, BuffSize);
  try
    Symbol^.SizeOfStruct := SizeOfStruct;
    Symbol^.MaxNameLength := MaxNameLength;
    Symbol^.Size := 0;
    SymLoadModule(FProcess, 0, PAnsiChar(AnsiString(ModuleName)),
      nil, BaseAddress, 0);
    try
      if SymGetSymFromAddr(FProcess, Address, @Displacement, Symbol) then
      begin
        if Displacement = 0 then
          Result := string(PAnsiChar(@(Symbol^).Name[0]));
      end
      else
      begin
        // с первой попытки может и не получиться
        SymLoadModule(FProcess, 0, PAnsiChar(AnsiString(ModuleName)), nil, BaseAddress, 0);
        if SymGetSymFromAddr(FProcess, Address, @Displacement, Symbol) then
          if Displacement = 0 then
            Result := string(PAnsiChar(@(Symbol^).Name[0]));
      end;
    finally
      SymUnloadModule(FProcess, BaseAddress);
    end;
  finally
    FreeMem(Symbol);
  end;
  if Result <> '' then
    Result := ExtractFileName(ModuleName) + '!' + Result;
end;

function TSymbols.GetDescriptionAtAddr(Address, BaseAddress: ULONG_PTR;
  const ModuleName: string): string;
const
  SizeOfStruct = SizeOf(TImagehlpSymbol);
  MaxNameLength = BuffSize - SizeOfStruct;
var
  Symbol: PImagehlpSymbol;
  Displacement: NativeUInt;
begin
  Result := '';
  if not FInited then Exit;
  GetMem(Symbol, BuffSize);
  try
    Symbol^.SizeOfStruct := SizeOfStruct;
    Symbol^.MaxNameLength := MaxNameLength;
    Symbol^.Size := 0;
    SymLoadModule(FProcess, 0, PAnsiChar(AnsiString(ModuleName)),
      nil, BaseAddress, 0);
    try
      if SymGetSymFromAddr(FProcess, Address, @Displacement, Symbol) then
      begin
        if Displacement = 0 then
          Result := string(PAnsiChar(@(Symbol^).Name[0]))
        else
          Result := string(PAnsiChar(@(Symbol^).Name[0])) + ' + 0x' + IntToHex(Displacement, 4);
      end
      else
      begin
        // с первой попытки может и не получиться
        SymLoadModule(FProcess, 0, PAnsiChar(AnsiString(ModuleName)), nil, BaseAddress, 0);
        if SymGetSymFromAddr(FProcess, Address, @Displacement, Symbol) then
          if Displacement = 0 then
            Result := string(PAnsiChar(@(Symbol^).Name[0]))
          else
            Result := string(PAnsiChar(@(Symbol^).Name[0])) + ' + 0x' + IntToHex(Displacement, 4);
      end;
    finally
      SymUnloadModule(FProcess, BaseAddress);
    end;
  finally
    FreeMem(Symbol);
  end;
  if Result = '' then
    Result := ExtractFileName(ModuleName) + ' + 0x' + IntToHex(Address - BaseAddress, 1)
  else
    Result := ExtractFileName(ModuleName) + '!' + Result;
end;

procedure TSymbols.GetExportFuncList(const ModuleName: string;
  BaseAddress: ULONG_PTR; Value: TStringList);
begin
  SymLoadModule(FProcess, 0, PAnsiChar(AnsiString(ModuleName)),
    nil, BaseAddress, 0);
  try
    if not SymEnumerateSymbols(FProcess, BaseAddress,
      @SymEnumsymbolsCallback, Value) then
    begin
      SymLoadModule(FProcess, 0, PAnsiChar(AnsiString(ModuleName)),
        nil, BaseAddress, 0);
      SymEnumerateSymbols(FProcess, BaseAddress,
        @SymEnumsymbolsCallback, Value)
    end;
  finally
    SymUnloadModule(FProcess, BaseAddress);
  end;
end;

procedure TSymbols.Init(BaseAddress: ULONG_PTR; const ModuleName: string);
var
  List: TStringList;
  Value: string;
begin
  FModuleName := ModuleName;
  FBaseAddress := BaseAddress;
  List := TStringList.Create;
  try
    GetExportFuncList(ModuleName, BaseAddress, List);
    for var I := 0 to List.Count - 1 do
      if FData.TryGetValue(List.Objects[I], Value) then
        FData.AddOrSetValue(List.Objects[I], Value + ';' + List[I])
      else
        FData.Add(List.Objects[I], List[I]);
  finally
    List.Free;
  end;
end;

procedure TSymbols.Release;
begin
  SymUnloadModule(FProcess, FBaseAddress);
end;

end.
