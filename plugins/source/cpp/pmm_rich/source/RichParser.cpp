////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RichParser.cpp
//  * Purpose   : Классы для парсинга Rich заголовков
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

#include "RichParser.h"
#include <fstream>
#include "ext.h"

void PeRichSignReader::Load(const wchar_t *filePath, ULONG64 hInst) 
{
	int cursor, size, index = 0; 
	DWORD mask = 0;
	ProdItem item = {};
	IMAGE_DOS_HEADER idh = {};

	data_.clear();
	
	// Зачитываем все целиком, так как искать будем с конца
	// За одно при нахождении маркера tagEndID автоматом рассчитаем
	// размер MS-DOS стаба
	std::ifstream image(filePath, std::ios::binary);
	image.read((char*)&idh, sizeof(IMAGE_DOS_HEADER));

	if (!idh.e_lfanew)
	{
		valid_ = FALSE;
		return;
	}

	cursor = size = idh.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	std::unique_ptr<byte[]> buff(new byte[size]);	

	image.read((char*)&buff[0], size);
	image.close();

	auto ReadDWORD = [&cursor, &buff]() 
	{		
		DWORD ret = 0;
		if (cursor >= 4) 
		{
			cursor -= 4;
			ret = *(DWORD*)(&buff[cursor]);
		}
		return ret;
	};

	// Rich идет сразу за DOS заголовком, учитываем его
	hInst += sizeof(IMAGE_DOS_HEADER);

	// Ищем начало
	while (cursor >= 8) 
	{
		item.count = ReadDWORD();
		item.prodID = ReadDWORD();
		item.addrVA = hInst + cursor;
		item.size = 8;
		if (item.prodID == tagBegID) 
		{
			item.itemType = ritBeginProdId;
			mask = item.count;
			data_.insert(data_.begin(), item);
			break;
		}
		else
		{
			item.itemType = ritNull;
		}
		data_.insert(data_.begin(), item);
	}

	// зачитываем все элементы с последнего по первый
	while (cursor >= 8) {
		index++;
		item.itemType = ritObject;
		item.count = ReadDWORD() ^ mask;
		item.prodID = ReadDWORD() ^ mask;
		item.addrVA = hInst + cursor;
		item.size = 8;
		if (item.prodID == tagEndID) 
		{
			item.itemType = ritEndProdId;
			data_.insert(data_.begin(), item);
			break;
		}
		else
		{
			data_.insert(data_.begin(), item);
		}
	}

	// проверка - все ли правильно?
	valid_ =
		(index) &&
		(data_.size() > 2) &&
		(data_[index].prodID == tagBegID) &&
		(data_[index].count != 0) && // контрольная сумма заголовка с расшифрованным Rich
		(data_[0].prodID == tagEndID) &&
		(data_[0].count == 0) &&
		(data_[1].prodID == 0) &&
		(data_[1].count == 0);

	// если все правильно, курсор расположен в самом конце
	// 16-битной MS-DOS заглушки, которую тоже добавляем в список
	// (если под неё осталось место)
	if ((valid_) && (cursor > 0)) {
		item.itemType = ritDosStub;
		item.addrVA = hInst;
		item.size = cursor;
		item.count = 0;
		item.prodID = 0;		
		data_.insert(data_.begin(), item);
	}
}

std::vector <ProdItem> PeRichSignReader::Items() 
{
	return data_;
}

BOOL PeRichSignReader::Valid() 
{
	return valid_;
}

void RichManager::OpenProcess(struct ProcessModule *list) 
{
	PeRichSignReader reader;

	data_.clear();
	while (list) {
		reader.Load(list->ImagePath, list->Instance);
		if (reader.Valid())
		{			
			std::vector <ProdItem> readerItems = reader.Items();
			data_.reserve(data_.size() + readerItems.size());
			data_.insert(data_.end(), readerItems.begin(), readerItems.end());
		}
		list = list->FLink;
	}
}

template<typename ... Args>
std::wstring format(const std::string& fmt, Args ... args)
{
	// C++11 specify that string store elements continously
	std::string tmp;

	size_t sz = std::snprintf(nullptr, 0, fmt.c_str(), args...);
	tmp.reserve(sz + 1); tmp.resize(sz);    // to be sure there have room for \0
	std::snprintf(&tmp.front(), tmp.capacity() + 1, fmt.c_str(), args...);

	std::wstring ret(tmp.begin(), tmp.end());
	return ret;
}

BOOL RichManager::GetDescriptorData(int index, struct DescriptorRawData* data) 
{
	if ((index < 0) || (index >= data_.size()))
		return FALSE;

	ProdItem item = data_[index];
	data->size = item.size;

	if (item.itemType != ritDosStub)
	{
		data->nameSpace = L"Microsoft Linker ID Statistics";
	}

	switch (item.itemType)
	{
		case ritDosStub:
			data->nameSpace = L"MS-DOS Stub";
			break;
		case ritBeginProdId:
			data->caption = L"Begin ProductID (RichSign)";			
			data->description = format("Mask = 0x%.8d", item.count);
			break;
		case ritObject:
			if (!(item.prodID || item.count))
			{
				data->caption = L" "; // пробелом указываем что описание есть, но пустое!
				data->description = L"end of tallies (Masked)";
			}
			else
			{
				data->caption = GetItemVersion(item.prodID, item.count);
				data->description = GetItemDescription(item.prodID);
			}
			break;
		case ritEndProdId:
			data->caption = L"End ProductID";
			data->description = L"start of tallies (Masked)";		
	}
	return TRUE;
}

std::vector <ProdItem> RichManager::Items()
{
	return data_;
}

std::wstring RichManager::GetItemVersion(DWORD progId, DWORD count)
{
	std::wstring ret = format("Id: %.3d Build: %d Count: %d", HIWORD(progId), LOWORD(progId), count);
	return ret;
}

static inline void ltrim(std::wstring& s) {
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](wchar_t ch) {
		return !std::isspace(ch);
		}));
}

std::wstring RichManager::GetItemDescription(DWORD progId)
{
	std::wstring hiStr, loStr;

	// https://bytepointer.com/articles/the_microsoft_rich_header.htm
	switch HIWORD(progId)
	{
		case 1: hiStr = L"Total count of imported DLL functions referenced"; break;
		case 2: hiStr = L"LINK 5.10 (Visual Studio 97 SP3)"; break;
		case 3: hiStr = L"LINK 5.10 (Visual Studio 97 SP3) OMF to COFF conversion"; break;
		case 4: hiStr = L"LINK 6.00 (Visual Studio 98)"; break;
		case 5: hiStr = L"LINK 6.00 (Visual Studio 98) OMF to COFF conversion"; break;
		case 6: hiStr = L"CVTRES 5.00"; break;
		case 7: hiStr = L"VB 5.0 native code"; break;
		case 8: hiStr = L"VC++ 5.0 C/C++"; break;
		case 9: hiStr = L"VB 6.0 native code"; break;
		case 10: hiStr = L"VC++ 6.0 C"; break;
		case 11: hiStr = L"VC++ 6.0 C++"; break;
		case 12: hiStr = L"ALIASOBJ.EXE (CRT Tool that builds OLDNAMES.LIB)"; break;
		case 13: hiStr = L"VB 6.0 generated object"; break;
		case 14: hiStr = L"MASM 6.13"; break;
		case 15: hiStr = L"MASM 7.01"; break;
		case 16: hiStr = L"LINK 5.11"; break;
		case 17: hiStr = L"LINK 5.11 OMF to COFF conversion"; break;
		case 18: hiStr = L"MASM 6.14 (MMX2 support)"; break;
		case 19: hiStr = L"LINK 5.12"; break;
		case 20: hiStr = L"LINK 5.12 OMF to COFF conversion"; break;
		case 42: hiStr = L"MASM 6.15"; break;
	}

	// https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.21
	switch LOWORD(progId)
	{
		case 7299: loStr = L"MASM 6.13"; break;
		case 8444: loStr = L"MASM 6.14"; break;
		case 8803: loStr = L"MASM 6.15"; break;
		case 8169: loStr = L"Visual Basic 6.0"; break;
		case 8495: loStr = L"Visual Basic 6.0 SP3"; break;
		case 8877: loStr = L"Visual Basic 6.0 SP4"; break;
		case 8964: loStr = L"Visual Basic 6.0 SP5"; break;
		case 8168: loStr = L"Visual Studio 6.0 (RTM)"; break;
		case 8447: loStr = L"Visual Studio 6.0 SP3"; break;
		case 8799: loStr = L"Visual Studio 6.0 SP4"; break;
		case 8966: loStr = L"Visual Studio 6.0 SP5"; break;
		case 9044: loStr = L"Visual Studio 6.0 SP5 Processor Pack"; break;
		case 9782: loStr = L"Visual Studio 6.0 SP6"; break;
		case 9030: loStr = L"Visual Studio 7.0 2000 (BETA 1)"; break;
		case 9254: loStr = L"Visual Studio 7.0 2001 (BETA 2)"; break;
		case 9466: loStr = L"Visual Studio 7.0 2002"; break;
		case 9955: loStr = L"Visual Studio 7.0 2002 SP1"; break;
		case 3077: loStr = L"Visual Studio 7.1 2003 (cl.exe 13.10.3077)"; break;
		case 3052: loStr = L"Visual Studio 7.1 2003 Free Toolkit "; break;
		case 4035: loStr = L"Visual Studio 7.1 2003 (cl.exe 13.10.4035)"; break;
		case 6030: loStr = L"Visual Studio 7.1 2003 SP1"; break;
		case 50327: loStr = L"Visual Studio 8.0 2005 (Beta)"; break;
		case 50727: loStr = L"Visual Studio 8.0 2005"; break;
		case 21022: loStr = L"Visual Studio 9.0 2008"; break;
		case 30411: loStr = L"Visual Studio 9.0 2008 ?"; break;
		case 30729: loStr = L"Visual Studio 9.0 2008 SP1"; break;
		case 30319: loStr = L"Visual Studio 10.0 2010"; break;
		case 40219: loStr = L"Visual Studio 10.0 2010 SP1"; break;
		//case 50727: loStr = L"Visual Studio 11.0 2012 (cl.exe 17.00.50727)"; break;
		case 51025: loStr = L"Visual Studio 11.0 2012"; break;
		case 51106: loStr = L"Visual Studio 11.0 2012 update 1"; break;
		case 60315: loStr = L"Visual Studio 11.0 2012 update 2"; break;
		case 60610: loStr = L"Visual Studio 11.0 2012 update 3"; break;
		case 61030: loStr = L"Visual Studio 11.0 2012 update 4"; break;
		case 21005: loStr = L"Visual Studio 12.0 2013"; break;
		case 30501: loStr = L"Visual Studio 12.0 2013 update 2"; break;
		case 31101: loStr = L"Visual Studio 12.0 2013 update 4"; break;
		case 40629: loStr = L"Visual Studio 12.0 2013 SP5"; break;
		case 40660: loStr = L"Visual Studio 12.0 2013 SP?"; break;
		case 22215: loStr = L"Visual Studio 14.0 2015 (cl.exe 19.00.22215 Preview)"; break;
		case 23026: loStr = L"Visual Studio 14.0 2015 (cl.exe 19.00.23026.0)"; break;
		case 23506: loStr = L"Visual Studio 14.0 2015 SP1"; break;
		case 23824: loStr = L"Visual Studio 14.0 2015 update 2"; break;
		case 23918:
		case 24212: loStr = L"Visual Studio 14.0 2015"; break;
		case 24215: loStr = L"Visual Studio 14.0 2015 (cl.exe 19.00.24215.1)"; break;
		case 24218: loStr = L"Visual Studio 14.0 2015 (cl.exe 19.00.24218.2)"; break;
		case 25017: loStr = L"Visual Studio 14.? 2017"; break;
		case 25019: loStr = L"Visual Studio 14.1 2017"; break;
		case 29112: loStr = L"Visual Studio 14.27 2019"; break;
		case 30133: loStr = L"Visual Studio 16.? 2019"; break;
		case 31630: loStr = L"Visual Studio 17.3 2022"; break;
	}

	if (!hiStr.empty())
	{
		if (loStr.empty())
		{
			loStr = hiStr;
		}
		else
		{
			loStr = hiStr + L", " + loStr;
		}
	}

	return loStr;
}