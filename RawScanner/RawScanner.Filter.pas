////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Filter.pas
//  * Purpose   : Класс для быстрой фильтрации результатов анализатора.
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

unit RawScanner.Filter;

interface

uses
  Classes,
  SysUtils,
  Generics.Collections,
  RawScanner.Types;

const
  FilterAll = '*';
  AllHookTypes = [htImport..htCode];
  ArrowMarker = ' -> ';

type
  TFilterStatus = (fsNone, fsIgnore, fsCheck);
  TFilter = class
  private type
    TFilterData = record
      HookType: THookTypes;
      FilterStatus: TFilterStatus;
    end;
  private
    FData: TObjectDictionary<string, TDictionary<string, TFilterData>>;
    FCheckList: TStringList;
    procedure InitDefaults;
    function CheckFuncTemplate(const Value: string): string;
  public
    constructor Create;
    destructor Destroy; override;
    /// <summary>
    ///  Добавление фильтра в список
    ///  HookHandler - библиотека в которую идет перенаправление
    ///  FuncTemplate - имя функции в формате "библиотека.имя"
    ///  на которой обнаружден перехватчик (например ntdll.RtlExitUserThread)
    ///  HookTypes - расположение установленого перехвата
    ///  FilterStatus - какой результат должен вернуть фильтр
    /// </summary>
    procedure AddFilter(HookHandler, FuncTemplate: string;
      HookTypes: THookTypes; FilterStatus: TFilterStatus);
    /// <summary>
    ///  Проверка фильтра
    ///  HookHandler - библиотека в которую идет перенаправление
    ///  FuncTemplate - имя функции "библиотека.имя" которую перенаправили
    ///  HookType - ресположение установленого перехвата
    /// </summary>
    function Check(HookHandler, FuncTemplate: string;
      HookType: THookType): TFilterStatus;
    procedure Clear;
    procedure CheckReset;
    function GetUncheckedCount: Integer;
    function GetUncheckedList: TStringList;
  end;

implementation

{ TFilter }

procedure TFilter.AddFilter(HookHandler, FuncTemplate: string;
  HookTypes: THookTypes; FilterStatus: TFilterStatus);
var
  LibraryData: TDictionary<string, TFilterData>;
  FilterData: TFilterData;
begin
  HookHandler := LowerCase(HookHandler);
  FuncTemplate := CheckFuncTemplate(FuncTemplate);
  if not FData.TryGetValue(HookHandler, LibraryData) then
  begin
    LibraryData := TDictionary<string, TFilterData>.Create;
    FData.Add(HookHandler, LibraryData);
  end;
  FilterData.HookType := HookTypes;
  FilterData.FilterStatus := FilterStatus;
  LibraryData.AddOrSetValue(FuncTemplate, FilterData);
  if FilterStatus = fsCheck then
    FCheckList.Add(FuncTemplate + ArrowMarker + HookHandler);
end;

function TFilter.Check(HookHandler, FuncTemplate: string;
  HookType: THookType): TFilterStatus;
var
  LibraryData: TDictionary<string, TFilterData>;
  FilterData: TFilterData;
  Index: Integer;
begin
  Result := fsNone;
  HookHandler := LowerCase(HookHandler);
  FuncTemplate := CheckFuncTemplate(FuncTemplate);
  if FData.TryGetValue(HookHandler, LibraryData) then
  begin
    try
      // проверка конкретного фильтра на библиотека + имя
      // например ntdll.RtlExitUserThread
      if LibraryData.TryGetValue(FuncTemplate, FilterData) then
      begin
        if HookType in FilterData.HookType then
          Result := FilterData.FilterStatus;
        Exit;
      end;
      // проверка фильтра на библиотеку + любая функция
      // например ntdll.*
      Index := LastDelimiter('.', FuncTemplate);
      if Index > 0 then
      begin
        FuncTemplate := Copy(FuncTemplate, 1, Index) + FilterAll;
        if LibraryData.TryGetValue(FuncTemplate, FilterData) then
        begin
          if HookType in FilterData.HookType then
            Result := FilterData.FilterStatus;
          Exit;
        end;
      end;
      // проверка фильтра на хэндлер хука
      // например *
      if LibraryData.TryGetValue(FilterAll, FilterData) then
      begin
        if HookType in FilterData.HookType then
          Result := FilterData.FilterStatus;
        Exit;
      end;
    finally
      if Result = fsCheck then
      begin
        Index := FCheckList.IndexOf(FuncTemplate + ArrowMarker + HookHandler);
        if Index >= 0 then
          FCheckList.Objects[Index] := Pointer(1);
      end;
    end;
  end;
end;

function TFilter.CheckFuncTemplate(const Value: string): string;
var
  Index: Integer;
begin
  Index := LastDelimiter('.', Value);
  if Index > 0 then
    Result := Copy(Value, 1, Index).ToLower +
      Copy(Value, Index + 1, Length(Value))
  else
    Result := Value;
end;

procedure TFilter.CheckReset;
begin
  for var I := 0 to FCheckList.Count - 1 do
    FCheckList.Objects[I] := nil;
end;

procedure TFilter.Clear;
begin
  FData.Clear;
  FCheckList.Clear;
end;

constructor TFilter.Create;
begin
  FData := TObjectDictionary<string,
    TDictionary<string, TFilterData>>.Create([doOwnsValues]);
  FCheckList := TStringList.Create;
  InitDefaults;
end;

destructor TFilter.Destroy;
begin
  FCheckList.Free;
  FData.Free;
  inherited;
end;

function TFilter.GetUncheckedCount: Integer;
begin
  Result := 0;
  for var I := 0 to FCheckList.Count - 1 do
    if FCheckList.Objects[I] = nil then
      Inc(Result);
end;

function TFilter.GetUncheckedList: TStringList;
begin
  Result := TStringList.Create;
  for var I := 0 to FCheckList.Count - 1 do
    if FCheckList.Objects[I] = nil then
      Result.Add(FCheckList[I]);
end;

procedure TFilter.InitDefaults;
begin
  AddFilter('apphelp.dll', FilterAll, [htImport, htDelayedImport], fsIgnore);
  AddFilter('kernelbase.dll', FilterAll, [htDelayedImport], fsIgnore);
end;

end.
