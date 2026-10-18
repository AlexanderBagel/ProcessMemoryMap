////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : RawScanner.Filter.pas
//  * Purpose   : A class for quickly filtering analyzer results.
//  *           : Not used within the framework,
//  *           : and intended for external code.
//  * Author    : Alexander (Rouse_) Bagel
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.2.30
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

unit RawScanner.Filter;

interface

  {$I rawscanner.inc}

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
    ///  Add a filter to the list
    /// </summary>
    /// <param name="HookHandler">the library to which the call is redirected</param>
    /// <param name="FuncTemplate">
    ///  the function name in the format "library.name"
    ///  on which the hook was detected (e.g., ntdll.RtlExitUserThread)
    /// </param>
    /// <param name="HookTypes">the location of the installed hook</param>
    /// <param name="FilterStatus">the result the filter should return</param>
    /// <remarks>
    ///  [ru] Добавление фильтра в список
    ///  HookHandler - библиотека, в которую идёт перенаправление
    ///  FuncTemplate - имя функции в формате "библиотека.имя"
    ///  на которой обнаружен перехват (например, ntdll.RtlExitUserThread)
    ///  HookTypes - расположение установленного перехвата
    ///  FilterStatus - какой результат должен вернуть фильтр
    /// </remarks>
    procedure AddFilter(HookHandler, FuncTemplate: string;
      HookTypes: THookTypes; FilterStatus: TFilterStatus);
    /// <summary>
    ///  Filter check
    /// </summary>
    /// <param name="HookHandler">the library to which the call is redirected</param>
    /// <param name="FuncTemplate">
    ///  the name of the function "library.name" that was redirected
    /// </param>
    /// <param name="HookType">the location of the installed hook</param>
    /// <remarks>
    ///  [ru] Проверка фильтра
    ///  HookHandler - библиотека, в которую идёт перенаправление
    ///  FuncTemplate - имя функции "библиотека.имя", которую перенаправили
    ///  HookType - расположение установленного перехвата
    /// </remarks>
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

      // Checking for a specific filter by library + name
      // for example, ntdll.RtlExitUserThread

      // [ru] Проверка конкретного фильтра на библиотеку + имя
      // например, ntdll.RtlExitUserThread

      if LibraryData.TryGetValue(FuncTemplate, FilterData) then
      begin
        if HookType in FilterData.HookType then
          Result := FilterData.FilterStatus;
        Exit;
      end;

      // Checking the filter for a library + any function
      // for example, ntdll.*

      // [ru] Проверка фильтра на библиотеку + любая функция
      // например, ntdll.*

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

      // Checking the filter for a hook handler
      // for example, *

      // [ru] Проверка фильтра на обработчик перехвата
      // например, *

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
