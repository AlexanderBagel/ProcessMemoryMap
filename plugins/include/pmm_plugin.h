////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : pmm_plugin.h
//  * Purpose   : Модуль с декларацией структур для плагинов PMM
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

#ifndef pmm_pluginH
#define pmm_pluginH

#include <windows.h>

/*
    Для облегчения отладки плагина можно использовать командную строку.
    1. В параметрах запуска указать путь к утилите (Host application).
       Например: ..\..\..\..\Win64\SingleInstance\ProcessMM.exe
    2. В командной строке прописать параметры запуска утилиты в формате
       "Идентификатор процесса" (int), "Адрес страницы" ($HEX), "режим дизассеблирования" (-d)       
       Например:  27992 $00540000 -d
    3. Для отладки 32 битной библиотеки необходимо переключить РММ в 32 битный режим
       принудительно выставлением флага x32 (только для 64 битных ОС)
       Например: x32 27992 $00540000 -d
*/


/// <summary>
/// версия API на которой был собран плагин, должна возвращаться в Plugin.VersionApi
/// </summary>

const int PMM_API_VER = 1;

/// <summary>
/// плагин должен экспортировать эту функцию, возвращающую структуру Plugin
/// </summary>

const char PMM_PLUGIN_ENTRYPOINT_NAME[] = "pmm_get_plugin_info";

/// <summary>
/// двусвязный список передаваемый на вход PluginOpenProcess
/// </summary>

struct ProcessModule
{
    struct ProcessModule *BLink; // ссылка на предыдущую структуру (или nil)
    struct ProcessModule *FLink; // ссылка на следующую структуру (nil - конец списка)
    ULONG64 Instance;            // база загрузки модуля в открытом хостом процессе
    wchar_t *ImagePath;          // полный путь к модулю
    BOOL LoadAsDataFile;         // флаг присутствия модуля в списках лоадера (исполняемый или отмапленый)
};

struct Descriptor
{
    ULONG64 AddrVA; // описываемый адрес
    HANDLE Handle;  // уникальный маркер задаваемый плагином
};

/// <summary>
/// данные описываемые дескриптором
/// </summary>

struct DescriptorData
{
    wchar_t *Caption;     // описание адреса, например имя функции или имя поля структуры
                          // необязательные поля (не используются в режиме дизассемблера)
    wchar_t *NameSpace;   // принадлежность адреса к более обьемному блоку (например структуре или таблице)
    wchar_t *Description; // коментарий у адресу
    DWORD Size;           // размер описываемого блока
};

/// <summary>
///  адреса функций посредством которых идет работа с плагином
///  Close является не обязательны и может быть не назначен.
/// </summary>

struct PluginCallGate
{
    /// <summary>
    ///  команда плагину об открытии нового процесса (нужно инициализароваться)
    ///  в случае успеха фунция должна вернуть NO_ERROR
    /// </summary>
    DWORD (WINAPI *PluginOpenProcess)(DWORD, struct ProcessModule *);
    /// <summary>
    ///  команда плагину о закрытии процесса (нужно освободить ресурсы)
    /// </summary>
    void (WINAPI *PluginCloseProcess)();
    /// <summary>
    ///  запрос о количестве известных плагину дескрипторов
    ///  в случае неуспеха функция должна вернуть ноль!
    /// </summary>
    int (WINAPI *PluginDescriptorCount)();
    /// <summary>
    /// запрос дескриптора по индексу
    /// </summary>
    DWORD (WINAPI *PluginGetDescriptor)(int, struct Descriptor *);
    /// <summary>
    ///  запрос данных дескриптора. Память должна быть выделена вызывающей стороной.
    ///  необходимый размер данных возвращается в параметре pSize
    ///  AHandle - параметр полученый ранее из структуры TDescriptor
    ///  Если pDescData равна NIL или pSize содержит недостаточный размер
    ///  функция обязана вернуть ERROR_INSUFFICIENT_BUFFER
    ///  В случае успеха функция должна вернуть NO_ERROR
    /// </summary>
    DWORD (WINAPI *PluginGetDescriptorData)(HANDLE, struct DescriptorData *, UINT32 *);
};

/// <summary>
/// структура возвращаемая pmm_get_plugin_info()
/// </summary>

struct Plugin
{
    DWORD VersionApi;            // поле должно быть заполнено значением PMM_API_VER
    DWORD PluginUID;             // уникальный идентификатор плагина.
                                 // не должен быть равен нулю и
                                 // не должен меняться при выпуске новой версии плагина!!!
    struct PluginCallGate Gate; // шлюз вызовов плагина

    // следующие поля не обязательны и могут быть равны nil
    const wchar_t *PluginName;        // имя плагина (используется в диалоге прогресса)
    const wchar_t *PluginAuthor;      // автор плагина
    const wchar_t *PluginHomePage;    // домашняя страницы плагина
    const wchar_t *PluginDescription; // краткое описание плагина
};

/// <summary>
/// точка входа в плагин. именно с неё начинается работа
/// </summary>

__declspec(dllexport) struct Plugin WINAPI pmm_get_plugin_info();

#endif //  pmm_pluginH