
#include <windows.h>
#include <stdio.h>
#include <string.h>

/*export*/ namespace metahook {

	typedef struct hook_s hook_t;

	class IBaseInterface;
	typedef IBaseInterface* (*CreateInterfaceFn)(const char* pName, int* pReturnCode);

	typedef struct metahook_api_s
	{
		BOOL(*UnHook)(hook_t* pHook);
		hook_t* (*InlineHook)(void* pOldFuncAddr, void* pNewFuncAddr, void*& pCallBackFuncAddr);
		hook_t* (*VFTHook)(void* pClass, int iTableIndex, int iFuncIndex, void* pNewFuncAddr, void*& pCallBackFuncAddr);
		hook_t* (*IATHook)(HMODULE hModule, const char* pszModuleName, const char* pszFuncName, void* pNewFuncAddr, void*& pCallBackFuncAddr);
		void* (*GetClassFuncAddr)(...);
		DWORD(*GetModuleBase)(HMODULE hModule);
		DWORD(*GetModuleSize)(HMODULE hModule);
		HMODULE (*GetEngineModule)(void);
		DWORD (*GetEngineBase)(void);
		DWORD (*GetEngineSize)(void);
		void* (*SearchPattern)(void* pStartSearch, DWORD dwSearchLen, const char* pPattern, DWORD dwPatternLen);
		void (*WriteDWORD)(void* pAddress, DWORD dwValue);
		DWORD(*ReadDWORD)(void* pAddress);
		DWORD(*WriteMemory)(void* pAddress, BYTE* pData, DWORD dwDataSize);
		DWORD(*ReadMemory)(void* pAddress, BYTE* pData, DWORD dwDataSize);
		[[deprecated]] DWORD (*GetVideoMode)(int *width, int *height, int *bpp, bool *windowed);
		DWORD (*GetEngineBuildnum)(void);
		[[deprecated]] CreateInterfaceFn (*GetEngineFactory)(void);
		DWORD(*GetNextCallAddr)(void* pAddress, DWORD dwCount);
		void (*WriteBYTE)(void* pAddress, BYTE ucValue);
		BYTE(*ReadBYTE)(void* pAddress);
		void (*WriteNOP)(void* pAddress, DWORD dwCount);
	}
	metahook_api_t;

	extern metahook_api_t* g_pMetaHookAPI;
}
