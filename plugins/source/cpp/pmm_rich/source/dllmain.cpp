////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : dllmain.cpp
//  * Purpose   : Demo plugin for displaying Rich headers
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

#include <string>
#include "RichParser.h"
#include "ext.h"

/*
* 
* The general purpose of a plugin for RMM is to generate descriptions for the addresses known to the plugin.
* On startup, the plugin must return a Plugin structure, through which the host will be
* given the plugin's parameters and the addresses of the gates the host will work through.
* There are five of them in total:
*
* 1. Gate.Open - this function is called when the host opens a process.
* It receives a doubly linked list of the opened process's modules and its PID.
* When this function is called, the plugin must initialize its data.
*
* 2. Gate.Close - the host has closed the process; the plugin may free all allocated data.
*
* 3. Gate.DescriptorCount - the host requests the number of descriptors known to the plugin.
* All data exchange takes place via descriptors, which are
* a Descriptor structure with two fields:
* AddrVA - the address described by the descriptor;
* Handle - a unique identifier known to the plugin, which the host
* will use to request extended information when processing the address.
* In this demo plugin, the Handle value is
* an index into the list of addresses known to the plugin, which are built from decoded
* and parsed Rich tables.
* 
* 4. Gate.GetDescriptor - the host requests a descriptor by index.
* 
* 5. Gate.GetDescriptorData - the host requests extended information for a descriptor.
* This extended information is what the host actually displays.
* The information is returned as a DescriptorData structure consisting
* of one mandatory field, Caption, which is always used
* (both when displaying information about structures, tables, etc. in Raw mode,
* and when displaying information in disassembler mode), and three optional fields,
* used for displaying structure / table fields (not used in disassembler mode),
* namely:
* NameSpace - specifies the name of the structure or table being described;
* Description - an arbitrary comment;
* Size - the size of the data described by the descriptor.
* 
*/

/* 
* [RU]
* Общая задача плагина для РММ - генерация описаний для известных плагину адресов.
* При старте плагин должен вернуть структуру Plugin в которой хосту будут
* переданы параметры плагина и адреса гейтов, через которые будет работать хост.
* их всего пять :
*
* 1. Gate.Open - эта функция вызывается при открытии процесса хостом
* На вход идет двусвязный список модулей открытого процесса и его PID
* При вызове этой функции плагин долже выполнить инициализацию данных
*
* 2. Gate.Close - хост закрыл процесс, плагин может освободить все занятые данные.
*
* 3. Gate.DescriptorCount - хост запрашивает количество известных плагину дескрипторов
* Весь обмен данными происходит посредством дескрипторов, представляющих из себя
* структуру Descriptor из двух полей
* AddrVA - адрес описываемый дескриптором
* Handle - некий уникальный идентификатор известный плагину, на основе которого
* хост будет запрашивать расширенную информацию при обработке адреса.
* В текущем демонстрационном плагине в качестве значения Handle используется
* индекс в списке известных плагину адресов, которые строятся из декодированых
* и распарсеных Rich таблиц.
* 
* 4. Gate.GetDescriptor - хост запрашивает дескриптор по индексу
* 
* 5. Gate.GetDescriptorData - хост запрашивает расширеную информацию по дескриптору
* именно эта расширеная информация и выводится хостом.
* Информация отдается ввиде структуры DescriptorData состоящей
* из одного обязательного поля - Caption, которое используется всегда,
* что для вывода информации по структурам / таблицам и прочему в режиме Raw,
* так и при выводе информации в режиме дизассеблера и трех не обязательных,
* применяемых для вывода полей структур / таблиц(не используются в режиме дизассемблера)
* А именно :
* NameSpace - указывает наименование описываемой структуры или таблицы
* Description - произвольный коментарий
* Size - размер данных описанных в дескрипторе
* 
*/

const DWORD PluginID = 0x72696368; // "rich"
std::wstring PluginName = L"Rich Signarure Parser (MS VC++ demo plugin.)";
std::wstring PluginAuthor = L"Alexander (Rouse_) Bagel";
std::wstring PluginHomePage = L"https://github.com/AlexanderBagel/ProcessMemoryMap/tree/master/plugins/source/cpp/pmm_rich/";
std::wstring PluginDescription = L"The plugin decodes the Rich structure in an executable file " \
    "(after the DOS-header) and displays information about known fields.";

RichManager *rich;

DWORD WINAPI PluginOpenProcess(DWORD processID, struct ProcessModule *list) 
{    
    if (!list) 
        return ERROR_INVALID_PARAMETER;
        
    try
    {        
        rich = new RichManager;
        rich->OpenProcess(list);

        return NO_ERROR;
    }
    catch (...) 
    {
        return ERROR_INVALID_DATA;
    }
}

void WINAPI PluginCloseProcess() 
{
    if (rich)
    {
        delete rich;
        rich = NULL;
    }
    return;
}

int WINAPI PluginDescriptorCount() 
{
    if (rich)
    {
        return (int)rich->Items().size();
    }
    return 0;
}

DWORD WINAPI PluginGetDescriptor(int index, struct Descriptor *pDesc)
{
    if (!rich) 
        return ERROR_DLL_INIT_FAILED;
    if ((index < 0) || (index >= rich->Items().size()))
        return ERROR_INVALID_PARAMETER;
    if (IsBadWritePtr(pDesc, sizeof(Descriptor)))
        return ERROR_INVALID_PARAMETER;
    pDesc->AddrVA = rich->Items()[(int)index].addrVA;
    pDesc->Handle = (HANDLE)(INT_PTR)index;
    pDesc->DescrType = PMM_DESCR_TYPE_STRUCT;
    return NO_ERROR;
}

DWORD WINAPI PluginGetDescriptorData(HANDLE index, struct DescriptorData *pDesc, UINT32 *nSize) 
{
    if (!rich)
        return ERROR_DLL_INIT_FAILED;

    if (IsBadReadPtr(nSize, 4))
        return ERROR_INVALID_PARAMETER;
    if (IsBadWritePtr(nSize, 4))
        return ERROR_INVALID_PARAMETER;

    RichManager::DescriptorRawData data;
    if (!rich->GetDescriptorData((int)(INT_PTR)index, &data))
        return ERROR_INVALID_PARAMETER;

    UINT32 size =
        (UINT32)(sizeof(DescriptorData) +
        (data.caption.length() + 1) * sizeof(wchar_t) +
        (data.description.length() + 1) * sizeof(wchar_t) +
        (data.nameSpace.length() + 1) * sizeof(wchar_t));

    if ((!pDesc) || (*nSize < size))
    {
        *nSize = size;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    if (IsBadWritePtr(pDesc, size))
        return ERROR_INVALID_PARAMETER;

    ZeroMemory(pDesc, size);
    size = sizeof(DescriptorData);
    pDesc->NameSpace = (wchar_t*)((ULONG64)pDesc + size);
    size = (UINT32)((data.nameSpace.length() + 1) * sizeof(wchar_t));
    if (size)
    {
        memcpy(pDesc->NameSpace, data.nameSpace.c_str(), size);
    }
    pDesc->Caption = (wchar_t*)((ULONG64)pDesc->NameSpace + size);
    size = (UINT32)((data.caption.length() + 1) * sizeof(wchar_t));
    if (size)
    {
        memcpy(pDesc->Caption, data.caption.c_str(), size);
    }
    pDesc->Description = (wchar_t*)((ULONG64)pDesc->Caption + size);
    size = (UINT32)((data.description.length() + 1) * sizeof(wchar_t));
    if (size)
    {
        memcpy(pDesc->Description, data.description.c_str(), size);
    }
    pDesc->Size = data.size;    
    return NO_ERROR;
}

__declspec(dllexport) struct Plugin WINAPI pmm_get_plugin_info() 
{
    Plugin plugin_info = {};
    plugin_info.VersionApi = PMM_API_VER;
    plugin_info.PluginUID = PluginID;

    plugin_info.Gate.PluginOpenProcess = PluginOpenProcess;
    plugin_info.Gate.PluginCloseProcess = PluginCloseProcess;
    plugin_info.Gate.PluginDescriptorCount = PluginDescriptorCount;
    plugin_info.Gate.PluginGetDescriptor = PluginGetDescriptor;
    plugin_info.Gate.PluginGetDescriptorData = PluginGetDescriptorData;

    plugin_info.PluginName = PluginName.c_str();
    plugin_info.PluginAuthor = PluginAuthor.c_str();
    plugin_info.PluginHomePage = PluginHomePage.c_str();
    plugin_info.PluginDescription = PluginDescription.c_str();

    return plugin_info;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}