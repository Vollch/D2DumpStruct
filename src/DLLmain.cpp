#define _D2VARS_H

#include "DLLmain.h"
#include "D2Patch.h"

/****************************************************************************
*                                                                           *
*   DLLmain.h                                                               *
*                                                                           *
*   Licensed under the Apache License, Version 2.0 (the "License");         *
*   you may not use this file except in compliance with the License.        *
*   You may obtain a copy of the License at                                 *
*                                                                           *
*   http://www.apache.org/licenses/LICENSE-2.0                              *
*                                                                           *
*   Unless required by applicable law or agreed to in writing, software     *
*   distributed under the License is distributed on an "AS IS" BASIS,       *
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.*
*   See the License for the specific language governing permissions and     *
*   limitations under the License.                                          *
*                                                                           *
*---------------------------------------------------------------------------*
*                                                                           *
*   https://github.com/olivier-verville/D2Template                          *
*                                                                           *
*   D2Template core file, do not modify unless you know what you're doing   *
*                                                                           *
*****************************************************************************/

void __fastcall D2TEMPLATE_FatalError(char* szMessage)
{
    MessageBoxA(NULL, szMessage, "D2DumpStruct", MB_OK | MB_ICONERROR);
    TerminateProcess(GetCurrentProcess(), -1);
}

BOOL __fastcall D2TEMPLATE_ApplyPatch(void* hGame, const DLLPatchStrc* hPatch)
{
    while (hPatch->nDLL != D2DLL_INVALID)
    {
        int nReturn = 0;
        int nDLL = hPatch->nDLL;
        if (nDLL < 0 || nDLL >= D2DLL_INVALID) return FALSE;
        
        DWORD dwAddress = hPatch->dwAddress;
        if (!dwAddress) return FALSE;

        DWORD dwBaseAddress = gptDllFiles[nDLL].dwAddress;
        if (!dwBaseAddress) return FALSE;

        dwAddress += dwBaseAddress;
        
        DWORD dwData = hPatch->dwData;
        if (hPatch->bRelative){ dwData = dwData - (dwAddress + sizeof(dwData)); }
        
        void* hAddress = (void*)dwAddress;
        DWORD dwOldPage;

        if (hPatch->nPatchSize > 0)
        {
            BYTE Buffer[1024];

            for (size_t i = 0; i < hPatch->nPatchSize; i++)
                Buffer[i] = (BYTE)dwData;

            VirtualProtect(hAddress, hPatch->nPatchSize, PAGE_EXECUTE_READWRITE, &dwOldPage);
            nReturn = WriteProcessMemory(hGame, hAddress, &Buffer, hPatch->nPatchSize, 0);
            VirtualProtect(hAddress, hPatch->nPatchSize, dwOldPage, 0);
        }

        else
        {
            VirtualProtect(hAddress, sizeof(dwData), PAGE_EXECUTE_READWRITE, &dwOldPage);
            nReturn = WriteProcessMemory(hGame, hAddress, &dwData, sizeof(dwData), 0);
            VirtualProtect(hAddress, sizeof(dwData), dwOldPage, 0);
        }
        
        if (nReturn == 0) return FALSE;
        
        hPatch++;
    }
    
    return TRUE;
}

BOOL __fastcall D2TEMPLATE_LoadModules()
{
    for (int i = 0; i < D2DLL_INVALID; i++)
    {
        DLLBaseStrc* hDllFile = &gptDllFiles[i];
        
        void* hModule = GetModuleHandle(hDllFile->szName);
        if (!hModule)
        {
            hModule = LoadLibrary(hDllFile->szName);
        }

        hDllFile->dwAddress = (DWORD)hModule;
    }

    return TRUE;
}

int __fastcall D2TEMPLATE_GetDebugPrivilege()
{
    void* hToken;
    LUID luid;
    TOKEN_PRIVILEGES tokenPrivileges;

    if (OpenProcessToken(GetCurrentProcess(),TOKEN_ALL_ACCESS,&hToken) == 0)
    {
        D2TEMPLATE_FatalError("OpenProcessToken Failed");
        return 0;
    }

    if (LookupPrivilegeValue(0,SE_DEBUG_NAME,&luid) == 0)
    {
        D2TEMPLATE_FatalError("LookupPrivilegeValue Failed");
        CloseHandle(hToken);
        return 0;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tokenPrivileges.Privileges[0].Luid = luid;
    if (AdjustTokenPrivileges(hToken,0,&tokenPrivileges,sizeof(tokenPrivileges),0,0) == 0)
    {
        D2TEMPLATE_FatalError("AdjustTokenPrivileges Failed");
        CloseHandle(hToken);
        return 0;
    }

    CloseHandle(hToken);
    return 1;
}

IMAGE_NT_HEADERS* GetHeader(LPBYTE pBase) {
	if (pBase == NULL)
		return NULL;

	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pBase;

	if (IsBadReadPtr(pDosHeader, sizeof(IMAGE_DOS_HEADER)))
		return NULL;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	IMAGE_NT_HEADERS* pHeader = (IMAGE_NT_HEADERS*)(pBase + pDosHeader->e_lfanew);
	if (IsBadReadPtr(pHeader, sizeof(IMAGE_NT_HEADERS)))
		return NULL;

	if (pHeader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return pHeader;
}

int __stdcall DllAttach()
{
    D2TEMPLATE_GetDebugPrivilege();

    void* hGame = GetCurrentProcess();
    if (!hGame) 
    {
        D2TEMPLATE_FatalError("Failed to retrieve process");
        return 0;
    }

    if (!D2TEMPLATE_LoadModules())
    {
        D2TEMPLATE_FatalError("Failed to load modules");
        return 0;
    }

    LPBYTE pBase = (LPBYTE) DLLBASE_D2COMMON;
    if (pBase == NULL)
    {
        return 0;
    }

    IMAGE_NT_HEADERS* pHeader = GetHeader(pBase);
    if (pHeader == NULL)
    {
        return 0;
    }

    if (pHeader->OptionalHeader.AddressOfEntryPoint == 0x00074D1D) { //109b
        dwHookOffset = 0x75D1;
        dwStackOffset = 0x248;
    }
    if (pHeader->OptionalHeader.AddressOfEntryPoint == 0x00074E2D) { //109d
        dwHookOffset = 0x75D1;
        dwStackOffset = 0x248;
    }
    if (pHeader->OptionalHeader.AddressOfEntryPoint == 0x000856DD) { //110f
        dwHookOffset = 0xFD88;
        dwStackOffset = 0x248;
    }
    if (pHeader->OptionalHeader.AddressOfEntryPoint == 0x00002C8D) { //111b
        dwHookOffset = 0xE871;
        dwStackOffset = 0x244;
    }
    if (pHeader->OptionalHeader.AddressOfEntryPoint == 0x00002C97) { //112a
        dwHookOffset = 0x41E61;
        dwStackOffset = 0x244;
    }
    if (pHeader->OptionalHeader.AddressOfEntryPoint == 0x00002C8F) { //113c
        dwHookOffset = 0x5EF51;
        dwStackOffset = 0x244;
    }

    if ( dwHookOffset )
    {
        dwRetAddr = gptDllFiles[D2DLL_D2COMMON].dwAddress + dwHookOffset + 0x08;
        gptTemplatePatches[0].dwAddress += dwHookOffset;
        gptTemplatePatches[1].dwAddress += dwHookOffset;
        gptTemplatePatches[2].dwAddress += dwHookOffset;
        D2TEMPLATE_ApplyPatch(hGame, gptTemplatePatches);
    }

    return 1;
}

int __stdcall DllMain(HINSTANCE hModule, DWORD dwReason, void* lpReserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            if (!DllAttach()) D2TEMPLATE_FatalError("Couldn't attach to Diablo II");
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            if (gpfBinStructs) fclose(gpfBinStructs);
            break;
        }
    }

    return TRUE;
}

DWORD __fastcall GetDllOffset(char* ModuleName, DWORD BaseAddress, int Offset)
{
	if(!BaseAddress)
		BaseAddress = (DWORD)LoadLibraryA(GetModuleExt(ModuleName));

	if(Offset < 0)
		return (DWORD)GetProcAddress((HMODULE)BaseAddress,(LPCSTR)(-Offset));

	return BaseAddress + Offset;
}

char* __fastcall GetModuleExt(char* ModuleName)
{
	char DLLExt[] = ".dll";
	char DLLName[32] = {0};
	strcpy(DLLName,ModuleName);
	return strcat(DLLName,DLLExt);
}