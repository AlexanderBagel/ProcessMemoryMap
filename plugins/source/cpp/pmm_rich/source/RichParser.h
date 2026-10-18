////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : RichParser.h
//  * Purpose   : Header files for the Rich header parsing classe
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

#pragma once

#include <windows.h>
#include <string>
#include <vector>

// data types in the order in which they usually appear in the header
enum RichItemType 
{
	ritDosStub,		// 16-bit DOS stub
	ritBeginProdId,	// start of the product ID list with the checksum
	ritObject,		// product IDs with counters
	ritEndProdId,	// end of the product ID list with the XOR key
	ritNull			// empty padding elements for alignment
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