////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RichParser.h
//  * Purpose   : Заголовки классов для парсинга Rich заголовков
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

#pragma once

#include <windows.h>
#include <string>
#include <vector>

// типы данных в том порядке в каком они обычно идут в заголовке
enum RichItemType 
{
	ritDosStub,		// 16-битный DOS стаб
	ritBeginProdId,	// начало списка идентификаторов с контрольной суммой
	ritObject,		// идентификаторы продуктов со счетчиками
	ritEndProdId,	// конец списка идентификаторов с XOR ключем
	ritNull			// пустые элементы для выравнивания
};

struct ProdItem 
{
	ULONG64 addrVA;
	DWORD size;
	DWORD prodID;	// Product identity
	DWORD count;	// Count of objects built with that product
	RichItemType itemType;
};

class PeRichSignReader
{
	public:	
		void Load(const wchar_t *filePath, ULONG64 hInst);

		std::vector <ProdItem> Items();
		BOOL Valid();

	private:
		static const int tagBegID = 0x68636952;
		static const int tagEndID = 0x536E6144;
		BOOL valid_ = FALSE;
		std::vector <ProdItem> data_;
};

class RichManager
{
	public:
		struct DescriptorRawData 
		{
			std::wstring nameSpace;
			std::wstring caption;
			std::wstring description;
			DWORD size = 0;
		};

		void OpenProcess(struct ProcessModule *list);
		BOOL GetDescriptorData(int index, struct DescriptorRawData *data);

		std::vector <ProdItem> Items();

	private:
		std::wstring GetItemVersion(DWORD, DWORD);
		std::wstring GetItemDescription(DWORD);
		std::vector <ProdItem> data_;
};