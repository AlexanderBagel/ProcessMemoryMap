////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : pmm_rich.dpr
//  * Purpose   : Демонстрационный плагин для отображения Rich заголовков
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

library pmm_rich;

uses
  Windows,
  System.SysUtils,
  System.Classes,
  pmm_plugin in '..\..\..\include\pmm_plugin.pas',
  uRichParser in 'uRichParser.pas';

{$R *.res}

{
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
  // уникальный UID плагина по которому он будет детектироваться без учета версий
  PluginUID = $72696368; // "rich"
  PluginName = 'Rich Signarure Parser (Delphi demo plugin)';
  PluginAuthor = 'Alexander (Rouse_) Bagel';
  PluginHomePage =
    'https://github.com/AlexanderBagel/ProcessMemoryMap/tree/master/plugins/source/delphi/pmm_rich/';
  PluginDesсription = 'The plugin decodes the Rich structure in an executable file ' +
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
  Result.PluginDesсription := @PluginDesсription[1];
end;

exports
  pmm_get_plugin_info;

begin
end.
