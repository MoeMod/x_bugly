#include "amxxmodule.h"

#pragma comment( lib, "dbghelp" )
#pragma comment( lib, "psapi" )
#include <Windows.h>
#include <winnt.h>
#include <dbghelp.h>
#include <psapi.h>
#include "metahook.h"

#include <vector>
#include <stdexcept>

void TryThrowAMX();
void Sys_PrintLog(const char* str);

typedef ULONG_PTR DWORD_PTR, * PDWORD_PTR;

int ModuleName(HANDLE process, char* name, void* address, int len)
{
	DWORD_PTR   baseAddress = 0;
	static HMODULE* moduleArray;
	static unsigned int moduleCount;
	LPBYTE      moduleArrayBytes;
	DWORD       bytesRequired;

	if (len < 3)
		return 0;

	if (!moduleArray && EnumProcessModules(process, NULL, 0, &bytesRequired))
	{
		if (bytesRequired)
		{
			moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

			if (moduleArrayBytes)
			{
				if (EnumProcessModules(process, (HMODULE*)moduleArrayBytes, bytesRequired, &bytesRequired))
				{
					moduleCount = bytesRequired / sizeof(HMODULE);
					moduleArray = (HMODULE*)moduleArrayBytes;
				}
			}
		}
	}

	for (unsigned int i = 0; i < moduleCount; i++)
	{
		MODULEINFO info;
		GetModuleInformation(process, moduleArray[i], &info, sizeof(MODULEINFO));

		if ((address > info.lpBaseOfDll) &&
			((DWORD64)address < (DWORD64)info.lpBaseOfDll + (DWORD64)info.SizeOfImage))
			return GetModuleBaseName(process, moduleArray[i], name, len);
	}
	return snprintf(name, len, "???");
}
static void PrintCxxStackTrace(PEXCEPTION_POINTERS pInfo)
{
	char message[1024];
	int len = 0;
	size_t i;
	HANDLE process = GetCurrentProcess();
	HANDLE thread = GetCurrentThread();
	IMAGEHLP_LINE64 line;
	DWORD dline = 0;
	DWORD options;
	CONTEXT context;
	STACKFRAME64 stackframe;
	DWORD image;

	memcpy(&context, pInfo->ContextRecord, sizeof(CONTEXT));
	options = SymGetOptions();
	options |= SYMOPT_DEBUG;
	options |= SYMOPT_LOAD_LINES;
	SymSetOptions(options);

	SymInitialize(process, NULL, TRUE);



	ZeroMemory(&stackframe, sizeof(STACKFRAME64));

#ifdef _M_IX86
	image = IMAGE_FILE_MACHINE_I386;
	stackframe.AddrPC.Offset = context.Eip;
	stackframe.AddrPC.Mode = AddrModeFlat;
	stackframe.AddrFrame.Offset = context.Ebp;
	stackframe.AddrFrame.Mode = AddrModeFlat;
	stackframe.AddrStack.Offset = context.Esp;
	stackframe.AddrStack.Mode = AddrModeFlat;
#elif _M_X64
	image = IMAGE_FILE_MACHINE_AMD64;
	stackframe.AddrPC.Offset = context.Rip;
	stackframe.AddrPC.Mode = AddrModeFlat;
	stackframe.AddrFrame.Offset = context.Rsp;
	stackframe.AddrFrame.Mode = AddrModeFlat;
	stackframe.AddrStack.Offset = context.Rsp;
	stackframe.AddrStack.Mode = AddrModeFlat;
#elif _M_IA64
	image = IMAGE_FILE_MACHINE_IA64;
	stackframe.AddrPC.Offset = context.StIIP;
	stackframe.AddrPC.Mode = AddrModeFlat;
	stackframe.AddrFrame.Offset = context.IntSp;
	stackframe.AddrFrame.Mode = AddrModeFlat;
	stackframe.AddrBStore.Offset = context.RsBSP;
	stackframe.AddrBStore.Mode = AddrModeFlat;
	stackframe.AddrStack.Offset = context.IntSp;
	stackframe.AddrStack.Mode = AddrModeFlat;
#endif
	len += snprintf(message + len, 1024 - len, "Sys_Crash: address %p, code %p\n", pInfo->ExceptionRecord->ExceptionAddress, (void*)pInfo->ExceptionRecord->ExceptionCode);
	if (SymGetLineFromAddr64(process, (DWORD64)pInfo->ExceptionRecord->ExceptionAddress, &dline, &line))
	{
		len += snprintf(message + len, 1024 - len, "Exception: %s:%d:%d\n", (char*)line.FileName, (int)line.LineNumber, (int)dline);
	}
	if (SymGetLineFromAddr64(process, stackframe.AddrPC.Offset, &dline, &line))
	{
		len += snprintf(message + len, 1024 - len, "PC: %s:%d:%d\n", (char*)line.FileName, (int)line.LineNumber, (int)dline);
	}
	if (SymGetLineFromAddr64(process, stackframe.AddrFrame.Offset, &dline, &line))
	{
		len += snprintf(message + len, 1024 - len, "Frame: %s:%d:%d\n", (char*)line.FileName, (int)line.LineNumber, (int)dline);
	}
	for (i = 0; i < 25; i++)
	{
		char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
		PSYMBOL_INFO symbol = (PSYMBOL_INFO)buffer;
		BOOL result = StackWalk64(
			image, process, thread,
			&stackframe, &context, NULL,
			SymFunctionTableAccess64, SymGetModuleBase64, NULL);

		DWORD64 displacement = 0;
		if (!result)
			break;


		symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		symbol->MaxNameLen = MAX_SYM_NAME;

		len += snprintf(message + len, 1024 - len, "% 2d %p", i, (void*)stackframe.AddrPC.Offset);
		if (SymFromAddr(process, stackframe.AddrPC.Offset, &displacement, symbol))
		{
			len += snprintf(message + len, 1024 - len, " %s ", symbol->Name);
		}
		if (SymGetLineFromAddr64(process, stackframe.AddrPC.Offset, &dline, &line))
		{
			len += snprintf(message + len, 1024 - len, "(%s:%d:%d) ", (char*)line.FileName, (int)line.LineNumber, (int)dline);
		}
		len += snprintf(message + len, 1024 - len, "(");
		len += ModuleName(process, message + len, (void*)stackframe.AddrPC.Offset, 1024 - len);
		len += snprintf(message + len, 1024 - len, ")\n");
	}
	Sys_PrintLog(message);
	MessageBox(NULL, message, ":(", MB_OK | MB_ICONSTOP);
	SymCleanup(process);
}

LPTOP_LEVEL_EXCEPTION_FILTER       oldFilter;
long _stdcall Sys_Crash(PEXCEPTION_POINTERS pInfo)
{
	// log amxx
	TryThrowAMX();

	// save config
	PrintCxxStackTrace(pInfo);

	if (oldFilter)
		return oldFilter(pInfo);
	return EXCEPTION_CONTINUE_EXECUTION;
}

void Sys_SetupCrashHandler(void)
{
	SetErrorMode(SEM_FAILCRITICALERRORS);	// no abort/retry/fail errors
	oldFilter = SetUnhandledExceptionFilter(Sys_Crash);
	[[maybe_unused]] auto hInst = GetModuleHandle(NULL);
}

void Sys_RestoreCrashHandler(void)
{
	// restore filter
	if (oldFilter) SetUnhandledExceptionFilter(oldFilter);
}

class Debugger;
std::vector<Debugger*> g_vecDebuggerStack;

void (__fastcall *g_pfnDebugger_BeginExec)(Debugger* that, int edx) = nullptr;
metahook::hook_t *g_hookDebugger_BeginExec = nullptr;
void __fastcall Hook_Debugger_BeginExec(Debugger* that, int edx)
{
	g_vecDebuggerStack.push_back(that);
	return g_pfnDebugger_BeginExec(that, edx);
}
void (__fastcall *g_pfnDebugger_EndExec)(Debugger* that, int edx) = nullptr;
metahook::hook_t* g_hookDebugger_EndExec = nullptr;
void __fastcall Hook_Debugger_EndExec(Debugger* that, int edx)
{
	g_vecDebuggerStack.pop_back();
	return g_pfnDebugger_EndExec(that, edx);
}
void (__fastcall *g_pfnDebugger_DisplayTrace)(Debugger* that, int edx, const char *msg) = nullptr;

AMX* Debugger_GetAMX(Debugger* that)
{
	AMX* amx = reinterpret_cast<AMX*>(that);
	return amx;
}

void TryThrowAMX()
{
	if (!g_vecDebuggerStack.empty())
	{
		Debugger* dbg = g_vecDebuggerStack.back();
		//AMX* amx = Debugger_GetAMX(dbg);
		//MF_RaiseAmxError(amx, AMX_ERR_NATIVE);
		if (g_pfnDebugger_DisplayTrace)
			g_pfnDebugger_DisplayTrace(dbg, 0, "[x_bugly] Crashed: ");
	}
}

void Sys_PrintLog(const char* str)
{
	puts(str);
	MF_Log("[x_bugly] %s\n", str);
}

[[noreturn]] static cell AMX_NATIVE_CALL x_bugly_crash_nullptr(AMX* amx, cell* params)
{
	return *(int*)0 = 0;
}
[[noreturn]] static cell AMX_NATIVE_CALL x_bugly_crash_throw(AMX* amx, cell* params)
{
	throw std::runtime_error("f**k you");
}
[[noreturn]] static cell AMX_NATIVE_CALL x_bugly_crash_use_after_free(AMX* amx, cell* params)
{
	int* array = new int[100];
	delete[] array;
	return array[1] = 1;
}
[[noreturn]] static cell AMX_NATIVE_CALL x_bugly_crash_heap_index(AMX* amx, cell* params)
{
	int* array = new int[100];
	array[1] = 0;
	int res = array[100 + 2];
	res = 5;
	array[100 + 103] = res;
	delete[] array;
	return res;
}
[[noreturn]] static cell AMX_NATIVE_CALL x_bugly_crash_stack_index(AMX* amx, cell* params)
{
	int shift = params[1];
	int stack_array[100];
	stack_array[2] = 5;
	int add = stack_array[2];
	int res = stack_array[100 + add];
	res = 3;
	return stack_array[100 + shift] = res;
}
[[noreturn]] static cell AMX_NATIVE_CALL x_bugly_crash_math(AMX* amx, cell* params)
{
	return (int)params / 0;
}
AMX_NATIVE_INFO Plugin_Natives[] =
{
	{"x_bugly_crash_nullptr",			x_bugly_crash_nullptr},
	{"x_bugly_crash_throw",			x_bugly_crash_throw},
	{"x_bugly_crash_use_after_free",			x_bugly_crash_use_after_free},
	{"x_bugly_crash_heap_index",			x_bugly_crash_heap_index},
	{"x_bugly_crash_stack_index",			x_bugly_crash_stack_index},
	{"x_bugly_crash_math",			x_bugly_crash_math},
	{NULL,				NULL},
};

void ServerActivate_Post(edict_t*, int, int)
{
	Sys_SetupCrashHandler();

	using namespace metahook;
	HMODULE hAmxxModule = GetModuleHandle("amxmodx_mm");
	auto dwAmxxBase = reinterpret_cast<void*>(g_pMetaHookAPI->GetModuleBase(hAmxxModule));
	auto dwAmxxSize = g_pMetaHookAPI->GetModuleSize(hAmxxModule);
	MF_PrintSrvConsole("[x_bugly] amxmodx_mm base at %p, %x\n", dwAmxxBase, dwAmxxSize);
	constexpr char ANY = 0x2A;
	constexpr char END = '\0';

	char SIG_Debugger_BeginExec[] = { 0x57,0x8B,0xF9,0xFF,0x47,ANY,0x8B,0x47,ANY,0x3B,0x47,ANY,0x7C,ANY,0x55,0x6A,ANY,0xE8,ANY,ANY,ANY,ANY,0x33,0xED,END };
	char SIG_Debugger_BeginExec2[] = { 0x57,0x8B,0xF9,0x83,0x47,ANY,ANY,0x8B,0x47,ANY,0x3B,0x47,ANY,0x7C,ANY,0x55,0x6A,ANY,0xE8,ANY,ANY,ANY,ANY,0x33,0xED,END };
	auto pfnDebugger_BeginExec = g_pMetaHookAPI->SearchPattern(dwAmxxBase, dwAmxxSize, SIG_Debugger_BeginExec, sizeof(SIG_Debugger_BeginExec) - 1);
	if(!pfnDebugger_BeginExec)
		pfnDebugger_BeginExec = g_pMetaHookAPI->SearchPattern(dwAmxxBase, dwAmxxSize, SIG_Debugger_BeginExec2, sizeof(SIG_Debugger_BeginExec2) - 1);
	MF_PrintSrvConsole("[x_bugly] Found Debugger::BeginExec at %p\n", pfnDebugger_BeginExec);
	
	char SIG_Debugger_EndExec[] = { 0x56,0x8B,0xF1,0x8B,0x46,ANY,0x8B,0x4E,ANY,0x8B,0x0C,0x81,0xE8,ANY,ANY,ANY,ANY,0xFF,0x4E,ANY,0x5E,0xC3,END };
	char SIG_Debugger_EndExec2[] = { 0x56,0x8B,0xF1,0x8B,0x46,ANY,0x8B,0x4E,ANY,0x8B,0x0C,0x81,0xE8,ANY,ANY,ANY,ANY,0x83,0x46,ANY,ANY,0x5E,0xC3,END };
	auto pfnDebugger_EndExec = g_pMetaHookAPI->SearchPattern(dwAmxxBase, dwAmxxSize, SIG_Debugger_EndExec, sizeof(SIG_Debugger_EndExec) - 1);
	if (!pfnDebugger_EndExec)
		pfnDebugger_EndExec = g_pMetaHookAPI->SearchPattern(dwAmxxBase, dwAmxxSize, SIG_Debugger_EndExec2, sizeof(SIG_Debugger_EndExec2) - 1);
	MF_PrintSrvConsole("[x_bugly] Found Debugger::EndExec at %p\n", pfnDebugger_EndExec);

	char SIG_Debugger_DisplayTrace[] = { 
		// sub esp, ?
		0x81,0xEC,ANY,ANY,ANY,ANY,
		// mov eax, ?
		0xA1,ANY,ANY,ANY,ANY,
		// xor eax, esp
		0x33,0xC4,
		// mov [esp+?+?], eax
		0x89,0x84,0x24,ANY,ANY,ANY,ANY,
		// mov eax, [esp+?+?]
		0x8B,0x84,0x24,ANY,ANY,ANY,ANY,
		// push ebx
		0x53,
		// push esi
		0x56,
		// push edi
		0x57,
		// mov edi,ecx
		0x8B,0xF9,
		// test eax, eax
		0x85,0xC0,
		// jz ?
		0x74,ANY,
		// push eax
		0x50,
		END
	};
	char SIG_Debugger_DisplayTrace2[] = {
		// sub esp, ?
		0x81,0xEC,ANY,ANY,ANY,ANY,
		// mov eax, ?
		0xA1,ANY,ANY,ANY,ANY,
		// xor eax, esp
		0x33,0xC4,
		// mov [esp+?+?], eax
		0x89,0x84,0x24,ANY,ANY,ANY,ANY,
		// mov eax, [esp+?+?]
		0x8B,0x84,0x24,ANY,ANY,ANY,ANY,
		// test eax, eax
		0x85,0xC0,
		// push ebx
		0x53,
		// push esi
		0x56,
		// push edi
		0x57,
		// mov edi,ecx
		0x8B,0xF9,
		// jz ?
		0x74,ANY,
		// push eax
		0x50,
		END
	};
	auto pfnDebugger_DisplayTrace = g_pMetaHookAPI->SearchPattern(dwAmxxBase, dwAmxxSize, SIG_Debugger_DisplayTrace, sizeof(SIG_Debugger_DisplayTrace) - 1);
	if(!pfnDebugger_DisplayTrace)
		pfnDebugger_DisplayTrace = g_pMetaHookAPI->SearchPattern(dwAmxxBase, dwAmxxSize, SIG_Debugger_DisplayTrace2, sizeof(SIG_Debugger_DisplayTrace2) - 1);
		
	MF_PrintSrvConsole("[x_bugly] Found Debugger::DisplayTrace at %p\n", pfnDebugger_DisplayTrace);

	g_hookDebugger_BeginExec = g_pMetaHookAPI->InlineHook(pfnDebugger_BeginExec, Hook_Debugger_BeginExec, (void*&)g_pfnDebugger_BeginExec);
	g_hookDebugger_EndExec = g_pMetaHookAPI->InlineHook(pfnDebugger_EndExec, Hook_Debugger_EndExec, (void*&)g_pfnDebugger_EndExec);
	g_pfnDebugger_DisplayTrace = (void(__fastcall *)(Debugger * that, int edx, const char* msg))pfnDebugger_DisplayTrace;
}

void ServerDeactivate_Post(void)
{
	Sys_RestoreCrashHandler();

	using namespace metahook;
	g_pMetaHookAPI->UnHook(g_hookDebugger_BeginExec);
	g_pMetaHookAPI->UnHook(g_hookDebugger_EndExec);
}

void OnAmxxAttach(void)
{
	MF_AddNatives(Plugin_Natives);
}

void OnPluginsLoaded(void)
{
	// regierster_forward
}