////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Unit Name : CallStackTraceUtils
//  * Purpose   : Реализация дампа текущего стека вызовов
//  * Author    : Александр (Rouse_) Багель
//  * Version   : 1.00
//  ****************************************************************************
//

unit CallStackTraceUtils;

interface

uses
  Windows,
  Classes,
  SysUtils,
  PsAPI,
  MemoryMap.Symbols,
  MemoryMap.DebugMapData,
  MemoryMap.Utils;

  function GetCallStack(BaseAddr: NativeUInt = $400000): TStringList;

implementation

type
  SYMBOL_INFO = packed record
    SizeOfStruct: ULONG;
    TypeIndex: ULONG;
    Reserved: array[0..1] of ULONG64;
    Index: ULONG;
    Size: ULONG;
    ModBase: ULONG64;
    Flags: ULONG;
    Value: ULONG64;
    Address: ULONG64;
    Register: ULONG;
    Scope: ULONG;
    Tag: ULONG;
    NameLen: ULONG;
    MaxNameLen: ULONG;
    Name: array[0..0] of AnsiChar;
  end;
  PSymbolInfo = ^SYMBOL_INFO;

  function RtlCaptureStackBackTrace(FramesToSkip, FramesToCapture: ULONG;
    BackTrace: PPVOID; BackTraceHash: PULONG): USHORT; stdcall; external kernel32;

function GetBaseAddr(AAddress: NativeUInt): NativeUInt;
var
  Info: TMemoryBasicInformation;
begin
  if VirtualQuery(Pointer(AAddress), Info, SizeOf(TMemoryBasicInformation)) <> 0 then
    Result := NativeUInt(Info.BaseAddress)
  else
    Result := 0;
end;

function GetModuleNameFromAddr(AAddress: NativeUInt): string;
var
  Len: Cardinal;
begin
  SetLength(Result, MAX_PATH);
  Len := GetMappedFileName(GetCurrentProcess, Pointer(AAddress),
    @Result[1], MAX_PATH);
  SetLength(Result, Len);
  Result := NormalizePath(Result);
end;

function GetFunction(const Value: string): string;
var
  Index: Integer;
begin
  Index := Pos('+', Value);
  if Index > 0 then
    Result := Trim(Copy(Value, 1, Index - 1))
  else
    Result := '';
end;

function GetDescriptionAtAddr(AAddress: NativeUInt; ASymbols: TSymbols;
  AMap: TDebugMap): string;
var
  LineNumber: Integer;
  AUnitName, AFuncName: string;
  BaseAddr: NativeUInt;
begin
  LineNumber := AMap.GetLineNumberAtAddrForced(AAddress, 400, AUnitName);
  AFuncName := AMap.GetDescriptionAtAddrWithOffset(AAddress);
  if LineNumber <= 0 then
  begin
    BaseAddr := GetBaseAddr(AAddress);
    Result := ASymbols.GetDescriptionAtAddr(AAddress, BaseAddr, GetModuleNameFromAddr(BaseAddr));
    Result := Format('%.8x: %s', [AAddress, Result]);
  end
  else
  begin
    AFuncName := GetFunction(AFuncName);
    Result := Format('%.8x: %s line %d', [AAddress, AFuncName, LineNumber]);
  end;
end;

function GetCallStack(BaseAddr: NativeUInt): TStringList;
var
  Map: TDebugMap;
  Symbols: TSymbols;
  Stack: array[0..127] of NativeUInt;
  I: Integer;
begin
  Result := TStringList.Create;
  try
    Map := TDebugMap.Create;
    try
      Map.LoadLines := True;
      if FileExists(ChangeFileExt(ParamStr(0), '.map')) then
        Map.Init(BaseAddr, ParamStr(0));
      Symbols := TSymbols.Create(GetCurrentProcess);
      try
        for I := 1 to RtlCaptureStackBackTrace(0, 127, @Stack, nil) - 1 do
          Result.Add(GetDescriptionAtAddr(Stack[I], Symbols, Map));
      finally
        Symbols.Free;
      end;
    finally
      Map.Free;
    end;
  except
    FreeAndNil(Result);
    raise;
  end;
end;

end.
