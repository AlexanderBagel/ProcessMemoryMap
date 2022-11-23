////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : pmm_plugin.pas
//  * Purpose   : Модуль с декларацией структур для плагинов PMM
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2022.
//  * Version   : 1.3.19
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit pmm_plugin;

interface

uses
  Windows;

{
    Для облегчения отладки плагина можно использовать командную строку.
    1. В параметрах запуска указать путь к утилите (Host application).
       Например: ..\..\..\..\Win64\SingleInstance\ProcessMM.exe
    2. В командной строке прописать параметры запуска утилиты в формате
       "Идентификатор процесса" (int), "Адрес страницы" ($HEX), "режим дизассеблирования" (-d)
       Например:  27992 $00540000 -d
    3. Для отладки 32 битной библиотеки необходимо переключить РММ в 32 битный режим
       принудительно выставлением флага x32 (только для 64 битных ОС)
       Например: x32 27992 $00540000 -d
}

const
  /// <summary>
  /// версия API на которой был собран плагин, должна возвращаться в TPlugin.VersionApi
  /// </summary>
  PMM_API_VER = 1;

  /// <summary>
  /// плагин должен экспортировать эту функцию, возвращающую структуру TPlugin
  /// </summary>
  PMM_PLUGIN_ENTRYPOINT_NAME = 'pmm_get_plugin_info';

type
  /// <summary>
  /// двусвязный список передаваемый на вход TPluginOpenProcess
  /// </summary>
  PProcessModule = ^TProcessModule;
  TProcessModule = record
    BLink: PProcessModule;   // ссылка на предыдущую структуру (или nil)
    FLink: PProcessModule;   // ссылка на следующую структуру (nil - конец списка)
    Instance: ULONG64;       // база загрузки модуля в открытом хостом процессе
    ImagePath: PWideChar;    // полный путь к модулю
    LoadAsDataFile: BOOL;    // флаг присутствия модуля в списках лоадера (исполняемый или отмапленый)
  end;

  /// <summary>
  ///  команда плагину об открытии нового процесса (нужно инициализароваться)
  ///  в случае успеха фунция должна вернуть NO_ERROR
  /// </summary>
  TPluginOpenProcess =
    function(AProcessID: DWORD; AModuleList: PProcessModule): DWORD; stdcall;

  /// <summary>
  ///  команда плагину о закрытии процесса (нужно освободить ресурсы)
  /// </summary>
  TPluginCloseProcess = procedure(); stdcall;

  /// <summary>
  ///  запрос о количестве известных плагину дескрипторов
  ///  в случае неуспеха функция должна вернуть ноль!
  /// </summary>
  TPluginDescriptorCount = function(): Integer; stdcall;

  /// <summary>
  /// уникальный описатель известной плагину информации по адресу
  /// </summary>
  PDescriptor = ^TDescriptor;
  TDescriptor = record
    AddrVA: ULONG64;     // описываемый адрес
    Handle: THandle;     // уникальный маркер задаваемый плагином
  end;

  /// <summary>
  /// запрос дескриптора по индексу
  /// </summary>
  TPluginGetDescriptor = function(Index: Integer; pDesc: PDescriptor): DWORD; stdcall;

  /// <summary>
  /// данные описываемые дескриптором
  /// </summary>
  PDescriptorData = ^TDescriptorData;
  TDescriptorData = record
    Caption: PWideChar;       // описание адреса, например имя функции или имя поля структуры
    // необязательные поля (не используются в режиме дизассемблера)
    NameSpace: PWideChar;     // принадлежность адреса к более обьемному блоку (например структуре или таблице)
    Description: PWideChar;   // коментарий к адресу
    Size: DWORD;              // размер описываемого блока
  end;

  /// <summary>
  ///  запрос данных дескриптора. Память должна быть выделена вызывающей стороной.
  ///  необходимый размер данных возвращается в параметре pSize
  ///  AHandle - параметр полученый ранее из структуры TDescriptor
  ///  Если pDescData равна NIL или pSize содержит недостаточный размер
  ///  функция обязана вернуть ERROR_INSUFFICIENT_BUFFER
  ///  В случае успеха функция должна вернуть NO_ERROR
  /// </summary>
  TPluginGetDescriptorData = function(AHandle: THandle;
    pDescData: PDescriptorData; pSize: PInteger): DWORD; stdcall;

  /// <summary>
  ///  адреса функций посредством которых идет работа с плагином
  ///  Close является не обязательны и может быть не назначен.
  /// </summary>
  TPluginCallGate = record
    Open: TPluginOpenProcess;
    Close: TPluginCloseProcess;
    DescriptorCount: TPluginDescriptorCount;
    GetDescriptor: TPluginGetDescriptor;
    GetDescriptorData: TPluginGetDescriptorData;
  end;

  /// <summary>
  /// структура возвращаемая pmm_get_plugin_info()
  /// </summary>
  TPlugin = record
    VersionApi: DWORD;              // поле должно быть заполнено значением PMM_API_VER
    PluginUID: DWORD;               // уникальный идентификатор плагина.
                                    // не должен быть равен нулю и
                                    // не должен меняться при выпуске новой версии плагина!!!

    Gate: TPluginCallGate;          // шлюз вызовов плагина

    // следующие поля не обязательны и могут быть равны nil
    PluginName: PWideChar;          // имя плагина (используется в диалоге прогресса)
    PluginAuthor: PWideChar;        // автор плагина
    PluginHomePage: PWideChar;      // домашняя страницы плагина
    PluginDesсription: PWideChar;   // краткое описание плагина
  end;

  /// <summary>
  /// точка входа в плагин. именно с неё начинается работа
  /// </summary>
  Tpmm_get_plugin_info = function(): TPlugin; stdcall;

implementation

end.
