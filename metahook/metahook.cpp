#include "metahook.h"
#include <detours/detours.h> // vcpkg install detours

namespace metahook {
	struct hook_s
	{
		void* pOldFuncAddr;
		void* pNewFuncAddr;
		void* pClass;
		int iTableIndex;
		int iFuncIndex;
		HMODULE hModule;
		const char* pszModuleName;
		const char* pszFuncName;
		struct hook_s* pNext;
		void* pInfo;
	};

	hook_t* g_pHookBase = nullptr;

	hook_t* MH_FindInlineHooked(void* pOldFuncAddr);
	hook_t* MH_FindVFTHooked(void* pClass, int iTableIndex, int iFuncIndex);
	hook_t* MH_FindIATHooked(HMODULE hModule, const char* pszModuleName, const char* pszFuncName);
	BOOL MH_UnHook(hook_t* pHook);
	hook_t* MH_InlineHook(void* pOldFuncAddr, void* pNewFuncAddr, void*& pCallBackFuncAddr);
	hook_t* MH_VFTHook(void* pClass, int iTableIndex, int iFuncIndex, void* pNewFuncAddr, void*& pCallBackFuncAddr);
	hook_t* MH_IATHook(HMODULE hModule, const char* pszModuleName, const char* pszFuncName, void* pNewFuncAddr, void*& pCallBackFuncAddr);
	void* MH_GetClassFuncAddr(...);
	DWORD MH_GetModuleBase(HMODULE hModule);
	DWORD MH_GetModuleSize(HMODULE hModule);
	void* MH_SearchPattern(void* pStartSearch, DWORD dwSearchLen, const char* pPattern, DWORD dwPatternLen);
	void MH_WriteDWORD(void* pAddress, DWORD dwValue);
	DWORD MH_ReadDWORD(void* pAddress);
	void MH_WriteBYTE(void* pAddress, BYTE ucValue);
	BYTE MH_ReadBYTE(void* pAddress);
	void MH_WriteNOP(void* pAddress, DWORD dwCount);
	DWORD MH_WriteMemory(void* pAddress, BYTE* pData, DWORD dwDataSize);
	DWORD MH_ReadMemory(void* pAddress, BYTE* pData, DWORD dwDataSize);

	extern metahook_api_t gMetaHookAPI;

	hook_t* MH_NewHook(void)
	{
		hook_t* h = new hook_t;
		memset(h, 0, sizeof(hook_t));
		h->pNext = g_pHookBase;
		g_pHookBase = h;
		return h;
	}

	hook_t* MH_FindInlineHooked(void* pOldFuncAddr)
	{
		for (hook_t* h = g_pHookBase; h; h = h->pNext)
		{
			if (h->pOldFuncAddr == pOldFuncAddr)
				return h;
		}

		return NULL;
	}

	hook_t* MH_FindVFTHooked(void* pClass, int iTableIndex, int iFuncIndex)
	{
		for (hook_t* h = g_pHookBase; h; h = h->pNext)
		{
			if (h->pClass == pClass && h->iTableIndex == iTableIndex && h->iFuncIndex == iFuncIndex)
				return h;
		}

		return NULL;
	}

	hook_t* MH_FindIATHooked(HMODULE hModule, const char* pszModuleName, const char* pszFuncName)
	{
		for (hook_t* h = g_pHookBase; h; h = h->pNext)
		{
			if (h->hModule == hModule && h->pszModuleName == pszModuleName && h->pszFuncName == pszFuncName)
				return h;
		}

		return NULL;
	}

#pragma pack(push, 1)

	struct tagIATDATA
	{
		void* pAPIInfoAddr;
	};

	struct tagCLASS
	{
		DWORD* pVMT;
	};

	struct tagVTABLEDATA
	{
		tagCLASS* pInstance;
		void* pVFTInfoAddr;
	};

#pragma pack(pop)

	void MH_FreeHook(hook_t* pHook)
	{
		if (pHook->pClass)
		{
			tagVTABLEDATA* info = (tagVTABLEDATA*)pHook->pInfo;
			MH_WriteMemory(info->pVFTInfoAddr, (BYTE*)pHook->pOldFuncAddr, sizeof(DWORD));
		}
		else if (pHook->hModule)
		{
			tagIATDATA* info = (tagIATDATA*)pHook->pInfo;
			MH_WriteMemory(info->pAPIInfoAddr, (BYTE*)pHook->pOldFuncAddr, sizeof(DWORD));
		}
		else
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(void*&)pHook->pOldFuncAddr, pHook->pNewFuncAddr);
			DetourTransactionCommit();
		}

		if (pHook->pInfo)
			delete pHook->pInfo;

		delete pHook;
	}

	void MH_FreeAllHook(void)
	{
		hook_t* next = NULL;

		for (hook_t* h = g_pHookBase; h; h = next)
		{
			next = h->pNext;
			MH_FreeHook(h);
		}

		g_pHookBase = NULL;
	}

	BOOL MH_UnHook(hook_t* pHook)
	{
		if (!g_pHookBase)
			return FALSE;

		hook_t* h, ** back;
		back = &g_pHookBase;

		while (1)
		{
			h = *back;

			if (!h)
				break;

			if (h == pHook)
			{
				*back = h->pNext;
				MH_FreeHook(h);
				return TRUE;
			}

			back = &h->pNext;
		}

		return FALSE;
	}

	hook_t* MH_InlineHook(void* pOldFuncAddr, void* pNewFuncAddr, void*& pCallBackFuncAddr)
	{
		hook_t* h = MH_NewHook();
		h->pOldFuncAddr = pOldFuncAddr;
		h->pNewFuncAddr = pNewFuncAddr;

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(void*&)h->pOldFuncAddr, pNewFuncAddr);
		DetourTransactionCommit();

		pCallBackFuncAddr = h->pOldFuncAddr;
		return h;
	}

	hook_t* MH_VFTHook(void* pClass, int iTableIndex, int iFuncIndex, void* pNewFuncAddr, void*& pCallBackFuncAddr)
	{
		tagVTABLEDATA* info = new tagVTABLEDATA;
		info->pInstance = (tagCLASS*)pClass;

		DWORD* pVMT = ((tagCLASS*)pClass + iTableIndex)->pVMT;
		info->pVFTInfoAddr = pVMT + iFuncIndex;

		hook_t* h = MH_NewHook();
		h->pOldFuncAddr = (void*)pVMT[iFuncIndex];
		h->pNewFuncAddr = pNewFuncAddr;
		h->pInfo = info;
		h->pClass = pClass;
		h->iTableIndex = iTableIndex;
		h->iFuncIndex = iFuncIndex;

		pCallBackFuncAddr = h->pOldFuncAddr;
		MH_WriteMemory(info->pVFTInfoAddr, (BYTE*)&pNewFuncAddr, sizeof(DWORD));
		return h;
	}

	hook_t* MH_IATHook(HMODULE hModule, const char* pszModuleName, const char* pszFuncName, void* pNewFuncAddr, void*& pCallBackFuncAddr)
	{
		IMAGE_NT_HEADERS* pHeader = (IMAGE_NT_HEADERS*)((DWORD)hModule + ((IMAGE_DOS_HEADER*)hModule)->e_lfanew);
		IMAGE_IMPORT_DESCRIPTOR* pImport = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)hModule + pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImport->Name && _stricmp((const char*)((DWORD)hModule + pImport->Name), pszModuleName))
			pImport++;

		DWORD dwFuncAddr = (DWORD)GetProcAddress(GetModuleHandleA(pszModuleName), pszFuncName);
		IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)((DWORD)hModule + pImport->FirstThunk);

		while (pThunk->u1.Function != dwFuncAddr)
			pThunk++;

		tagIATDATA* info = new tagIATDATA;
		info->pAPIInfoAddr = &pThunk->u1.Function;

		hook_t* h = MH_NewHook();
		h->pOldFuncAddr = (void*)pThunk->u1.Function;
		h->pNewFuncAddr = pNewFuncAddr;
		h->pInfo = info;
		h->hModule = hModule;
		h->pszModuleName = pszModuleName;
		h->pszFuncName = pszFuncName;

		pCallBackFuncAddr = h->pOldFuncAddr;
		MH_WriteMemory(info->pAPIInfoAddr, (BYTE*)&pNewFuncAddr, sizeof(DWORD));
		return h;
	}

	void* MH_GetClassFuncAddr(...)
	{
		DWORD address;

		__asm
		{
			lea eax, address
			mov edx, [ebp + 8]
			mov[eax], edx
		}

		return (void*)address;
	}

	DWORD MH_GetModuleBase(HMODULE hModule)
	{
		MEMORY_BASIC_INFORMATION mem;

		if (!VirtualQuery(hModule, &mem, sizeof(MEMORY_BASIC_INFORMATION)))
			return 0;

		return (DWORD)mem.AllocationBase;
	}

	DWORD MH_GetModuleSize(HMODULE hModule)
	{
		return ((IMAGE_NT_HEADERS*)((DWORD)hModule + ((IMAGE_DOS_HEADER*)hModule)->e_lfanew))->OptionalHeader.SizeOfImage;
	}

	void* MH_SearchPattern(void* pStartSearch, DWORD dwSearchLen, const char* pPattern, DWORD dwPatternLen)
	{
		DWORD dwStartAddr = (DWORD)pStartSearch;
		DWORD dwEndAddr = dwStartAddr + dwSearchLen - dwPatternLen;

		while (dwStartAddr < dwEndAddr)
		{
			bool found = true;

			for (DWORD i = 0; i < dwPatternLen; i++)
			{
				char code = *(char*)(dwStartAddr + i);

				if (pPattern[i] != 0x2A && pPattern[i] != code)
				{
					found = false;
					break;
				}
			}

			if (found)
				return (void*)dwStartAddr;

			dwStartAddr++;
		}

		return 0;
	}

	void MH_WriteDWORD(void* pAddress, DWORD dwValue)
	{
		DWORD dwProtect;

		if (VirtualProtect((void*)pAddress, 4, PAGE_EXECUTE_READWRITE, &dwProtect))
		{
			*(DWORD*)pAddress = dwValue;
			VirtualProtect((void*)pAddress, 4, dwProtect, &dwProtect);
		}
	}

	DWORD MH_ReadDWORD(void* pAddress)
	{
		DWORD dwProtect;
		DWORD dwValue = 0;

		if (VirtualProtect((void*)pAddress, 4, PAGE_EXECUTE_READWRITE, &dwProtect))
		{
			dwValue = *(DWORD*)pAddress;
			VirtualProtect((void*)pAddress, 4, dwProtect, &dwProtect);
		}

		return dwValue;
	}

	void MH_WriteBYTE(void* pAddress, BYTE ucValue)
	{
		DWORD dwProtect;

		if (VirtualProtect((void*)pAddress, 1, PAGE_EXECUTE_READWRITE, &dwProtect))
		{
			*(BYTE*)pAddress = ucValue;
			VirtualProtect((void*)pAddress, 1, dwProtect, &dwProtect);
		}
	}

	BYTE MH_ReadBYTE(void* pAddress)
	{
		DWORD dwProtect;
		BYTE ucValue = 0;

		if (VirtualProtect((void*)pAddress, 1, PAGE_EXECUTE_READWRITE, &dwProtect))
		{
			ucValue = *(BYTE*)pAddress;
			VirtualProtect((void*)pAddress, 1, dwProtect, &dwProtect);
		}

		return ucValue;
	}

	void MH_WriteNOP(void* pAddress, DWORD dwCount)
	{
		static DWORD dwProtect;

		if (VirtualProtect(pAddress, dwCount, PAGE_EXECUTE_READWRITE, &dwProtect))
		{
			for (DWORD i = 0; i < dwCount; i++)
				*(BYTE*)((DWORD)pAddress + i) = 0x90;

			VirtualProtect(pAddress, dwCount, dwProtect, &dwProtect);
		}
	}

	DWORD MH_WriteMemory(void* pAddress, BYTE* pData, DWORD dwDataSize)
	{
		static DWORD dwProtect;

		if (VirtualProtect(pAddress, dwDataSize, PAGE_EXECUTE_READWRITE, &dwProtect))
		{
			memcpy(pAddress, pData, dwDataSize);
			VirtualProtect(pAddress, dwDataSize, dwProtect, &dwProtect);
		}

		return dwDataSize;
	}

	DWORD MH_ReadMemory(void* pAddress, BYTE* pData, DWORD dwDataSize)
	{
		static DWORD dwProtect;

		if (VirtualProtect(pAddress, dwDataSize, PAGE_EXECUTE_READWRITE, &dwProtect))
		{
			memcpy(pData, pAddress, dwDataSize);
			VirtualProtect(pAddress, dwDataSize, dwProtect, &dwProtect);
		}

		return dwDataSize;
	}

	DWORD MH_GetNextCallAddr(void* pAddress, DWORD dwCount)
	{
		static BYTE* pbAddress = NULL;

		if (pAddress)
			pbAddress = (BYTE*)pAddress;
		else
			pbAddress = pbAddress + 5;

		for (DWORD i = 0; i < dwCount; i++)
		{
			BYTE code = *(BYTE*)pbAddress;

			if (code == 0xFF && *(BYTE*)(pbAddress + 1) == 0x15)
			{
				return *(DWORD*)(pbAddress + 2);
			}

			if (code == 0xE8)
			{
				return (DWORD)(*(DWORD*)(pbAddress + 1) + pbAddress + 5);
			}

			pbAddress++;
		}

		return 0;
	}

	struct EngineInfo
	{
		HMODULE hEngineModule;
		DWORD dwEngineBase;
		DWORD dwEngineSize;
		DWORD dwEngineBuildnum;
		DWORD dwDataSize;
		BOOL bEngineIsBlob;
		int (*pfnbuild_number)(void);
		bool bIsNewEngine;
	};

#define BUILD_NUMBER_SIG "\xA1\x2A\x2A\x2A\x2A\x83\xEC\x08\x2A\x33\x2A\x85\xC0"
#define BUILD_NUMBER_SIG_NEW "\x55\x8B\xEC\x83\xEC\x08\xA1\x2A\x2A\x2A\x2A\x56\x33\xF6\x85\xC0\x0F\x85\x2A\x2A\x2A\x2A\x53\x33\xDB\x8B\x04\x9D"

	EngineInfo MH_GetEngineInfoReal()
	{
		EngineInfo info;
		info.hEngineModule = GetModuleHandle("swds.dll");
		if (!info.hEngineModule || info.hEngineModule == INVALID_HANDLE_VALUE)
		{
			info.hEngineModule = GetModuleHandle("hw.dll");
		}
		if (!info.hEngineModule || info.hEngineModule == INVALID_HANDLE_VALUE)
		{
			info.hEngineModule = GetModuleHandle("sw.dll");
		}
		if (!info.hEngineModule || info.hEngineModule == INVALID_HANDLE_VALUE)
		{
			info.dwEngineBase = 0x1D01000;
			info.dwEngineSize = 0x1000000;
			info.bEngineIsBlob = TRUE;
		}
		else
		{
			info.dwEngineBase = MH_GetModuleBase(info.hEngineModule);
			info.dwEngineSize = MH_GetModuleSize(info.hEngineModule);
			info.bEngineIsBlob = FALSE;
		}

		info.bIsNewEngine = false;
		info.pfnbuild_number = (int (*)(void))MH_SearchPattern((void*)info.dwEngineBase, info.dwEngineSize, BUILD_NUMBER_SIG, sizeof(BUILD_NUMBER_SIG) - 1);

		if (!info.pfnbuild_number)
		{
			info.pfnbuild_number = (int (*)(void))MH_SearchPattern((void*)info.dwEngineBase, info.dwEngineSize, BUILD_NUMBER_SIG_NEW, sizeof(BUILD_NUMBER_SIG_NEW) - 1);
			info.bIsNewEngine = true;
		}
		return info;
	}

	EngineInfo MH_GetEngineInfo()
	{
		static const EngineInfo x = MH_GetEngineInfoReal();
		return x;
	}

	HMODULE MH_GetEngineModule()
	{
		return MH_GetEngineInfo().hEngineModule;
	}

	DWORD MH_GetEngineBase()
	{
		return MH_GetEngineInfo().dwEngineBase;
	}

	DWORD MH_GetEngineSize()
	{
		return MH_GetEngineInfo().dwEngineSize;
	}

	DWORD MH_GetEngineVersion(void)
	{
		auto pfn = MH_GetEngineInfo().pfnbuild_number;
		return pfn ? pfn() : 0;
	}

	void* g_dwEngineBase = 0;
	DWORD g_dwEngineSize = 0;
	DWORD g_dwEngineBuildnum = 0;
	DWORD g_dwDataSize = 0x02FFFFFF - 0x01D00000;

	metahook_api_t gMetaHookAPI =
	{
		MH_UnHook,
		MH_InlineHook,
		MH_VFTHook,
		MH_IATHook,
		MH_GetClassFuncAddr,
		MH_GetModuleBase,
		MH_GetModuleSize,
		MH_GetEngineModule,
		MH_GetEngineBase,
		MH_GetEngineSize,
		MH_SearchPattern,
		MH_WriteDWORD,
		MH_ReadDWORD,
		MH_WriteMemory,
		MH_ReadMemory,
		nullptr,
		MH_GetEngineVersion,
		nullptr,
		MH_GetNextCallAddr,
		MH_WriteBYTE,
		MH_ReadBYTE,
		MH_WriteNOP
	};

	metahook_api_t* g_pMetaHookAPI = &gMetaHookAPI;
}