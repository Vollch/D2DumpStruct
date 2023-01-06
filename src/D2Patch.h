#pragma once

#ifndef _D2PATCH_H
#define _D2PATCH_H

#include "D2PatchConst.h"

/****************************************************************************
*                                                                           *
*   D2Patch.h                                                               *
*   Copyright (C) Olivier Verville                                          *
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
*   This file is where you declare all your patches, in order to inject     *
*   your own code into the game. Each patch should be declared in the       *
*   array, in order to be handled by D2Template's patcher                   *
*                                                                           *
*****************************************************************************/

//void* __stdcall DATATBLS_CompileTxt(void* pMemPool, const char* szName, D2BinFieldStrc* pTbl, int* pRecordCount, size_t dwSize);
void __stdcall dumpStructs(void* pMemPool, const char* szName, D2BinFieldStrc* pTbl, int* pRecordCount, size_t dwSize)
{
    if ( !gpfBinStructs )
    {
        gpfBinStructs = fopen("BinStructs.txt", "w");
    }
    if ( gpfBinStructs )
    {
        fprintf(gpfBinStructs, "%s\t%u\n", szName, dwSize);
        while ( pTbl->nFieldType )
        {
            fprintf(gpfBinStructs, "%s\t%u\t%u\t%u\t%p\n", pTbl->szFieldName, pTbl->nFieldType, pTbl->nFieldLength, pTbl->nFieldOffset, pTbl->pLinkField);
            pTbl++;
        }
        fprintf(gpfBinStructs, "%s\t%u\t%u\t%u\t%p\n\n\n", pTbl->szFieldName, pTbl->nFieldType, pTbl->nFieldLength, pTbl->nFieldOffset, pTbl->pLinkField);
    }
    return;
}

__declspec(naked) void CompileBinHook()
{
	__asm
	{
        pushfd; // save current state
        pushad; // save current state

        mov ebx, esp; // get initial stack pointer
        add ebx, dwStackOffset; // add offset to the arguments of injected function

        push [ebx+0x10]; // dwSize
        push [ebx+0xC]; // pRecordCount
        push [ebx+0x8]; // pTbl
        push [ebx+0x4]; // szName
        push [ebx]; // pMemPool
        call dumpStructs; // call hook

        popad; // restore pre-hook state
        popfd; // restore pre-hook state
        mov dword ptr ss:[esp+0x10], 0x0; // repeat original code overwritten by patch
        jmp dwRetAddr; // jump back
    }
}

static DLLPatchStrc gptTemplatePatches[] =
{
    {D2DLL_D2COMMON, 0x0, (DWORD)PATCH_JMP, FALSE, 0x1},
    {D2DLL_D2COMMON, 0x1, (DWORD)CompileBinHook, TRUE, 0x0},
    {D2DLL_D2COMMON, 0x5, 0x90, FALSE, 0x3},
    {D2DLL_INVALID}
};

// end of file --------------------------------------------------------------
#endif