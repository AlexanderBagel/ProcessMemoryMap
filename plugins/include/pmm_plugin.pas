////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : pmm_plugin.pas
//  * Purpose   : Module containing structure declarations for PMM plugins
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

unit pmm_plugin;

interface

uses
  Windows;

{
    You can use the command line to facilitate plugin debugging.
    1. In the launch settings, specify the path to the utility (Host application).
       For example: ..\..\..\..\Win64\SingleInstance\ProcessMM.exe
    2. In the command line, specify the utility's launch parameters in the following format:
       "Process ID" (int), "Page address" ($HEX), "disassembly mode" (-d)
       For example:  27992 $00540000 -d
    3. To debug a 32-bit library, you must switch ProcessMM to 32-bit mode
       by forcing the x32 flag (only for 64-bit operating systems)
       For example: x32 27992 $00540000 -d


    [ru] Для облегчения отладки плагина можно использовать командную строку.
    1. В параметрах запуска указать путь к утилите (Host application).
       Например: ..\..\..\..\Win64\SingleInstance\ProcessMM.exe
    2. В командной строке прописать параметры запуска утилиты в формате
       "Идентификатор процесса" (int), "Адрес страницы" ($HEX), "режим дизассемблирования" (-d)
       Например:  27992 $00540000 -d
    3. Для отладки 32 битной библиотеки необходимо переключить РММ в 32 битный режим
       принудительно выставлением флага x32 (только для 64 битных ОС)
       Например: x32 27992 $00540000 -d
}

const
  /// <summary>
  ///  The API version used to build the plugin must be returned in TPlugin.VersionApi
  /// </summary>
  /// <remarks>
  ///  [ru] версия API на которой был собран плагин, должна возвращаться в TPlugin.VersionApi
  /// </remarks>
  PMM_API_VER = 1;


  /// <summary>
  ///  The plugin must export this function, which returns a TPlugin structure
  /// </summary>
  /// <remarks>
  ///  [ru] плагин должен экспортировать эту функцию, возвращающую структуру TPlugin
  /// </remarks>
  PMM_PLUGIN_ENTRYPOINT_NAME = 'pmm_get_plugin_info';

type
  /// <summary>
  ///  A doubly linked list passed as an argument to the TPluginOpenProcess function
  /// </summary>
  /// <remarks>
  ///  [ru] двусвязный список передаваемый на вход TPluginOpenProcess
  /// </remarks>
  PProcessModule = ^TProcessModule;
  TProcessModule = record

    // a reference to the previous structure (or nil)
    // [ru] ссылка на предыдущую структуру (или nil)

    BLink: PProcessModule;

    // a reference to the next structure (nil indicates the end of the list)
    // [ru] ссылка на следующую структуру (nil - конец списка)

    FLink: PProcessModule;

    // Module image base in the process opened by the host
    // [ru] база загрузки модуля в открытом хостом процессе

    Instance: ULONG64;

    // full path to the module
    // [ru] полный путь к модулю

    ImagePath: PWideChar;

    // flag indicating whether the module is present in the loader's lists (executable or mapped)
    // [ru] флаг присутствия модуля в списках лоадера (исполняемый или отмапленый)

    LoadAsDataFile: BOOL;
  end;

  /// <summary>
  ///  command to the plugin to open a new process (initialization is required)
  ///  if successful, the function must return NO_ERROR
  /// </summary>
  /// <remarks>
  ///  [ru] команда плагину об открытии нового процесса (нужно инициализироваться)
  ///  в случае успеха функция должна вернуть NO_ERROR
  /// </remarks>
  TPluginOpenProcess =
    function(AProcessID: DWORD; AModuleList: PProcessModule): DWORD; stdcall;

  /// <summary>
  ///  a command to the plugin to close the process (to free up resources)
  /// </summary>
  /// <remarks>
  ///  [ru] команда плагину о закрытии процесса (нужно освободить ресурсы)
  /// </remarks>
  TPluginCloseProcess = procedure(); stdcall;

  /// <summary>
  ///  request for the number of descriptors known to the plugin
  ///  if the request fails, the function must return zero!
  /// </summary>
  /// <remarks>
  ///  [ru] запрос о количестве известных плагину дескрипторов
  ///  в случае неуспеха функция должна вернуть ноль!
  /// </remarks>
  TPluginDescriptorCount = function(): Integer; stdcall;

  /// <summary>
  ///  flags for the data types contained in the descriptor
  /// </summary>
  /// <remarks>
  ///  [ru] флаги типов данных содержащихся в дескрипторе
  /// </remarks>
  TDescriptorType = (

    /// <summary>
    ///  arbitrary data described by a descriptor, such as a comment
    /// </summary>
    /// <remarks>
    ///  [ru] произвольные данные, описываемые дескриптором, например комментарий
    /// </remarks>
    PMM_DESCR_TYPE_UNKNOWN = 0,

    /// <summary>
    ///  the descriptor describes a structure field, in TDescriptorData,
    ///  it is recommended to enter the structure name in the NameSpace field
    /// </summary>
    /// <remarks>
    ///  [ru] дескриптор описывает поле структуры, при этом в TDescriptorData
    ///  желательно заполнение наименования структуры в поле NameSpace
    /// </remarks>
    PMM_DESCR_TYPE_STRUCT = 1,

    /// <summary>
    ///  a descriptor describes a function
    /// </summary>
    /// <remarks>
    ///  [ru] дескриптор описывает функцию
    /// </remarks>
    PMM_DESCR_TYPE_FUNCTION = 2
  );

  /// <summary>
  ///  a unique identifier for information known to the plugin at the address
  /// </summary>
  /// <remarks>
  ///  [ru] уникальный описатель известной плагину информации по адресу
  /// </remarks>
  PDescriptor = ^TDescriptor;
  TDescriptor = record

    // an address for which information is available
    // [ru] адрес для которого есть информация

    AddrVA: ULONG64;

    // a unique marker set by the plugin, used as a parameter in GetDescriptorData
    // [ru] уникальный маркер задаваемый плагином, используется как параметр в GetDescriptorData

    Handle: THandle;
    DescrType: TDescriptorType;
  end;

  /// <summary>
  ///  descriptor lookup by index
  /// </summary>
  /// <remarks>
  ///  [ru] запрос дескриптора по индексу
  /// </remarks>
  TPluginGetDescriptor = function(Index: Integer; pDesc: PDescriptor): DWORD; stdcall;

  /// <summary>
  ///  data described by the descriptor
  /// </summary>
  /// <remarks>
  ///  [ru] данные описываемые дескриптором
  /// </remarks>
  PDescriptorData = ^TDescriptorData;
  TDescriptorData = record

    // a description of the address, such as a function name or a structure field name
    // [ru] описание адреса, например имя функции или имя поля структуры

    Caption: PWideChar;

    // optional fields (not used in disassembler mode)
    // [ru] необязательные поля (не используются в режиме дизассемблера)

    // whether the address belongs to a larger block (such as a structure or a table)
    // [ru] принадлежность адреса к более объемному блоку (например структуре или таблице)

    NameSpace: PWideChar;

    // comment on the address
    // [ru] комментарий к адресу

    Description: PWideChar;

    // size of the block being described
    // [ru] размер описываемого блока

    Size: DWORD;
  end;

  /// <summary>
  ///  Request descriptor data. Memory must be allocated by the caller.
  ///  The required data size is returned in the pSize parameter
  ///  AHandle is a parameter previously obtained from the TDescriptor structure
  ///  If pDescData is NIL or pSize contains an insufficient size,
  ///  the function must return ERROR_INSUFFICIENT_BUFFER
  ///  If successful, the function must return NO_ERROR
  /// </summary>
  /// <remarks>
  ///  [ru] запрос данных дескриптора.
  ///  Память должна быть выделена вызывающей стороной.
  ///  необходимый размер данных возвращается в параметре pSize
  ///  AHandle - параметр полученный ранее из структуры TDescriptor
  ///  Если pDescData равна NIL или pSize содержит недостаточный размер
  ///  функция обязана вернуть ERROR_INSUFFICIENT_BUFFER
  ///  В случае успеха функция должна вернуть NO_ERROR
  /// </remarks>
  TPluginGetDescriptorData = function(AHandle: THandle;
    pDescData: PDescriptorData; pSize: PInteger): DWORD; stdcall;

  /// <summary>
  ///  Function handles used to interact with the plugin
  ///  Close() is optional and may be omitted.
  /// </summary>
  /// <remarks>
  ///  [ru] адреса функций посредством которых идет работа с плагином
  ///  Close() является не обязательной и может быть не назначена.
  /// </remarks>
  TPluginCallGate = record
    Open: TPluginOpenProcess;
    Close: TPluginCloseProcess;
    DescriptorCount: TPluginDescriptorCount;
    GetDescriptor: TPluginGetDescriptor;
    GetDescriptorData: TPluginGetDescriptorData;
  end;

  /// <summary>
  ///  Structure returned by pmm_get_plugin_info()
  /// </summary>
  /// <remarks>
  ///  [ru] структура возвращаемая pmm_get_plugin_info()
  /// </remarks>
  TPlugin = record

    // This field must be set to PMM_API_VER
    // [ru] поле должно быть заполнено значением PMM_API_VER

    VersionApi: DWORD;

    // The plugin's unique identifier.
    // It must not be zero, and
    // it must not change when a new version of the plugin is released!!!

    // [ru] уникальный идентификатор плагина.
    // Не должен быть равен нулю и
    // не должен меняться при выпуске новой версии плагина!!!

    PluginUID: DWORD;

    // plugin call gateway
    // [ru] шлюз вызовов плагина

    Gate: TPluginCallGate;

    // The following fields are optional and may be nil
    // [ru] следующие поля не обязательны и могут быть равны nil

    // plugin name (used in the progress dialog)
    // [ru] имя плагина (используется в диалоге прогресса)

    PluginName: PWideChar;

    PluginAuthor: PWideChar;
    PluginHomePage: PWideChar;
    PluginDescription: PWideChar;
  end;

  /// <summary>
  ///  The entry point for the plugin. This is where the plugin begins to run.
  /// </summary>
  /// <remarks>
  ///  [ru] точка входа в плагин. Именно с неё начинается работа
  /// </remarks>
  Tpmm_get_plugin_info = function(): TPlugin; stdcall;

implementation

end.
