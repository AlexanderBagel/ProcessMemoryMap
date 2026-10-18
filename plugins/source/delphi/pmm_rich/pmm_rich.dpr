////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : pmm_rich.dpr
//  * Purpose   : Демонстрационный плагин для отображения Rich заголовков
//  * Author    : Alexander (Rouse_) Bagel
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.7.54
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

library pmm_rich;

uses
  Windows,
  System.SysUtils,
  System.Classes,
  pmm_plugin in '..\..\..\include\pmm_plugin.pas',
  uRichParser in 'uRichParser.pas';

{$R *.res}


{
  The general purpose of a plugin for RMM is to generate descriptions for the addresses known to the plugin.
  On startup, the plugin must return a Plugin structure, through which the host will be
  given the plugin's parameters and the addresses of the gates the host will work through.
  There are five of them in total:

  1. Gate.Open - this function is called when the host opens a process.
     It receives a doubly linked list of the opened process's modules and its PID.
     When this function is called, the plugin must initialize its data.

  2. Gate.Close - the host has closed the process; the plugin may free all allocated data.

  3. Gate.DescriptorCount - the host requests the number of descriptors known to the plugin.
     All data exchange takes place via descriptors, which are
     a Descriptor structure with two fields:
     AddrVA - the address described by the descriptor;
     Handle - a unique identifier known to the plugin, which the host
     will use to request extended information when processing the address.
     In this demo plugin, the Handle value is
     an index into the list of addresses known to the plugin, which are built from decoded
     and parsed Rich tables.

  4. Gate.GetDescriptor - the host requests a descriptor by index.

  5. Gate.GetDescriptorData - the host requests extended information for a descriptor.
     This extended information is what the host actually displays.
     The information is returned as a DescriptorData structure consisting
     of one mandatory field, Caption, which is always used
     (both when displaying information about structures, tables, etc. in Raw mode,
     and when displaying information in disassembler mode), and three optional fields,
     used for displaying structure / table fields (not used in disassembler mode),
     namely:
     NameSpace - specifies the name of the structure or table being described;
     Description - an arbitrary comment;
     Size - the size of the data described by the descriptor.
}

{
  [RU]

  Общая задача плагина для РММ - генерация описаний для известных плагину адресов.
  При старте плагин должен вернуть структуру TPlugin в которой хосту будут
  переданы параметры плагина и адреса гейтов, через которые будет работать хост.
  их всего пять:

  1. Gate.Open - эта функция вызывается при открытии процесса хостом
     На вход идет двусвязный список модулей открытого процесса и его PID
     При вызове этой функции плагин долже выполнить инициализацию данных

  2. Gate.Close - хост закрыл процесс, плагин может освободить все занятые данные.

  3. Gate.DescriptorCount - хост запрашивает количество известных плагину дескрипторов
     Весь обмен данными происходит посредством дескрипторов, представляющих из себя
     структуру TDescriptor из двух полей
     AddrVA - адрес описываемый дескриптором
     Handle - некий уникальный идентификатор известный плагину, на основе которого
     хост будет запрашивать расширенную информацию при обработке адреса.
     В текущем демонстрационном плагине в качестве значения Handle используется
     индекс в списке известных плагину адресов, которые строятся из декодированых
     и распарсеных Rich таблиц.

  4. Gate.GetDescriptor - хост запрашивает дескриптор по индексу

  5. Gate.GetDescriptorData - хост запрашивает расширеную информацию по дескриптору
     именно эта расширеная информация и выводится хостом.
     Информация отдается ввиде структуры TDescriptorData состоящей
     из одного обязательного поля - Caption, которое используется всегда,
     что для вывода информации по структурам/таблицам и прочему в режиме Raw,
     так и при выводе информации в режиме дизассеблера и трех не обязательных,
     применяемых для вывода полей структур/таблиц (не используются в режиме дизассемблера)
     А именно:
     NameSpace - указывает наименование описываемой структуры или таблицы
     Description - произвольный коментарий
     Size - размер данных описанных в дескрипторе
}

const

  // Unique plugin UID used to detect the plugin regardless of version
  // [ru] уникальный UID плагина по которому он будет детектироваться без учета версий

  PluginUID = $72696368; // "rich"
  PluginName = 'Rich Signarure Parser (Delphi demo plugin)';
  PluginAuthor = 'Alexander (Rouse_) Bagel';
  PluginHomePage =
    'https://github.com/AlexanderBagel/ProcessMemoryMap/tree/master/plugins/source/delphi/pmm_rich/';
  PluginDescription = 'The plugin decodes the Rich structure in an executable file ' +
    '(after the DOS-header) and displays information about known fields.';

var
  RichManager: TRichManager = nil;

function PlgOpenProcess(AProcessID: DWORD; AModuleList: PProcessModule): DWORD; stdcall;
begin
  Result := ERROR_INVALID_PARAMETER;
  if RichManager = nil then
    RichManager := TRichManager.Create;
  try
    if Assigned(AModuleList) then
    begin
      RichManager.OpenProcess(AModuleList);
      Result := NO_ERROR;
    end;
  except
    Result := ERROR_INVALID_DATA;
  end;
end;

procedure PlgCloseProcess; stdcall;
begin
  FreeAndNil(RichManager);
end;

function PlgDescriptorCount: Integer; stdcall;
begin
  if Assigned(RichManager) then
    Result := RichManager.Items.Count
  else
    Result := 0;
end;

function PlgGetDescriptor(Index: Integer; pDesc: PDescriptor): DWORD; stdcall;
begin
  if RichManager = nil then
    Exit(ERROR_DLL_INIT_FAILED);
  if (Index < 0) or (Index >= PlgDescriptorCount) then
    Exit(ERROR_INVALID_PARAMETER);
  if IsBadWritePtr(pDesc, SizeOf(TDescriptor)) then
    Exit(ERROR_INVALID_PARAMETER);
  pDesc.AddrVA := RichManager.Items[Index].AddrVA;
  pDesc.Handle := Index;
  pDesc.DescrType := PMM_DESCR_TYPE_STRUCT;
  Result := NO_ERROR;
end;

function PlgGetDescriptorData(AHandle: THandle;
  pDescData: PDescriptorData; pSize: PInteger): DWORD; stdcall;
var
  Data: TRawData;
  Size: Integer;
begin
  if RichManager = nil then
    Exit(ERROR_DLL_INIT_FAILED);
  if IsBadReadPtr(pSize, 4) or IsBadWritePtr(pSize, 4) then
    Exit(ERROR_INVALID_PARAMETER);

  if not RichManager.GetDescriptorData(Integer(AHandle), Data) then
    Exit(ERROR_INVALID_PARAMETER);

  Size :=
    SizeOf(TDescriptorData) +
    Length(Data.NameSpace) shl 1 + 2 +
    Length(Data.Caption) shl 1 + 2 +
    Length(Data.Description) shl 1 + 2;
  if (pDescData = nil) or (pSize^ < Size) then
  begin
    pSize^ := Size;
    Exit(ERROR_INSUFFICIENT_BUFFER);
  end;
  if IsBadWritePtr(pDescData, Size) then
    Exit(ERROR_INVALID_PARAMETER);

  ZeroMemory(pDescData, Size);
  Size := SizeOf(TDescriptorData);
  pDescData.NameSpace := PChar(PByte(pDescData) + Size);
  Size := Length(Data.NameSpace) shl 1 + 2;
  pDescData.Caption := PChar(PByte(pDescData.NameSpace) + Size);
  Size := Length(Data.Caption) shl 1 + 2;
  pDescData.Description := PChar(PByte(pDescData.Caption) + Size);
  pDescData.Size := Data.Size;
  if Data.NameSpace <> EmptyStr then
    Move(Data.NameSpace[1], pDescData.NameSpace^, Length(Data.NameSpace) shl 1);
  if Data.Caption <> EmptyStr then
    Move(Data.Caption[1], pDescData.Caption^, Length(Data.Caption) shl 1);
  if Data.Description <> EmptyStr then
    Move(Data.Description[1], pDescData.Description^, Length(Data.Description) shl 1);
  Result := NO_ERROR;
end;

function pmm_get_plugin_info: TPlugin; stdcall;
begin
  ZeroMemory(@Result, SizeOf(TPlugin));
  Result.VersionApi := PMM_API_VER;
  Result.PluginUID := PluginUID;
  Result.Gate.Open := PlgOpenProcess;
  Result.Gate.Close := PlgCloseProcess;
  Result.Gate.DescriptorCount := PlgDescriptorCount;
  Result.Gate.GetDescriptor := PlgGetDescriptor;
  Result.Gate.GetDescriptorData := PlgGetDescriptorData;
  Result.PluginName := @PluginName[1];
  Result.PluginAuthor := @PluginAuthor[1];
  Result.PluginHomePage := @PluginHomePage[1];
  Result.PluginDescription := @PluginDescription[1];
end;

exports
  pmm_get_plugin_info;

begin
end.
