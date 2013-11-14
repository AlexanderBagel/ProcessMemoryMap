////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : MemoryMap
//  * Unit Name : MemoryMap.Symbols.pas
//  * Purpose   : Класс для работы с символами.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2013.
//  * Version   : 1.0
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
  Winapi.ImageHlp,
  System.Classes,
  System.SysUtils;

type
  TSymbols = class
  private
    FInited: Boolean;
    FProcess: THandle;
  public
    constructor Create(hProcess: THandle);
    destructor Destroy; override;
    function GetDescriptionAtAddr(Address, BaseAddress: ULONG_PTR;
      const ModuleName: string): string;
    procedure GetExportFuncList(const ModuleName: string;
      BaseAddress: ULONG_PTR; Value: TStringList);
  end;

implementation

const
  ImagehlpLib = 'IMAGEHLP.DLL';

type
  PImagehlpSymbol64 = ^TImagehlpSymbol64;
  _IMAGEHLP_SYMBOL64 = record
    SizeOfStruct: DWORD;
    Address: DWORD64;
    Size,
    Flags,
    MaxNameLength: DWORD;
    Name: packed array[0..0] of Byte;
  end;
  TImagehlpSymbol64 = _IMAGEHLP_SYMBOL64;

  {$IFDEF WIN64}
  function SymGetSymFromAddr(hProcess: THandle; dwAddr: ULONG_PTR;
    pdwDisplacement: PDWORD64; Symbol: PImagehlpSymbol64): Bool; stdcall;
    external ImagehlpLib name 'SymGetSymFromAddr64';
  function SymLoadModule(hProcess: THandle; hFile: THandle; ImageName,
    ModuleName: LPSTR; BaseOfDll: ULONG_PTR; SizeOfDll: DWORD): DWORD; stdcall;
    external ImagehlpLib name 'SymLoadModule64';
  function SymUnloadModule(hProcess: THandle; BaseOfDll: ULONG_PTR): Bool; stdcall;
    external ImagehlpLib name 'SymUnloadModule64';
  function SymEnumerateSymbols(hProcess: THandle; BaseOfDll: ULONG_PTR;
    EnumSymbolsCallback: TSymEnumSymbolsCallback; UserContext: Pointer): Bool; stdcall;
    external ImagehlpLib name 'SymEnumerateSymbols64';
  {$ELSE}
  function SymGetSymFromAddr(hProcess: THandle; dwAddr: ULONG_PTR;
    pdwDisplacement: PDWORD; Symbol: PImagehlpSymbol): Bool; stdcall;
    external ImagehlpLib;
  function SymLoadModule(hProcess: THandle; hFile: THandle; ImageName,
    ModuleName: LPSTR; BaseOfDll: ULONG_PTR; SizeOfDll: DWORD): DWORD; stdcall;
    external ImagehlpLib;
  function SymUnloadModule(hProcess: THandle; BaseOfDll: ULONG_PTR): Bool; stdcall;
    external ImagehlpLib;
  function SymEnumerateSymbols(hProcess: THandle; BaseOfDll: ULONG_PTR;
    EnumSymbolsCallback: TSymEnumSymbolsCallback; UserContext: Pointer): Bool; stdcall;
    external ImagehlpLib;
  {$ENDIF}

{ TSymbols }

constructor TSymbols.Create(hProcess: THandle);
begin
  FProcess := hProcess;
  SymSetOptions(SYMOPT_UNDNAME or SYMOPT_DEFERRED_LOADS);
  FInited := SymInitialize(hProcess, nil, True);
end;

destructor TSymbols.Destroy;
begin
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

function TSymbols.GetDescriptionAtAddr(Address, BaseAddress: ULONG_PTR;
  const ModuleName: string): string;
const
  BuffSize = $7FF;
{$IFDEF WIN64}
  SizeOfStruct = SizeOf(TImagehlpSymbol64);
  MaxNameLength = BuffSize - SizeOfStruct;
var
  Symbol: PImagehlpSymbol64;
  Displacement: DWORD64;
{$ELSE}
  SizeOfStruct = SizeOf(TImagehlpSymbol);
  MaxNameLength = BuffSize - SizeOfStruct;
var
  Symbol: PImagehlpSymbol;
  Displacement: DWORD;
{$ENDIF}
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
        Result := string(PAnsiChar(@(Symbol^).Name[0])) + ' + 0x' + IntToHex(Displacement, 4)
      else
      begin
        // с первой попытки может и не получиться
        SymLoadModule(FProcess, 0, PAnsiChar(AnsiString(ModuleName)), nil, BaseAddress, 0);
        if SymGetSymFromAddr(FProcess, Address, @Displacement, Symbol) then
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

end.
