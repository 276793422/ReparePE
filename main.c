#include <Windows.h>
#include <stdio.h>
#include <accctrl.h>
#include <aclapi.h>


static LPSTR __GetFileContent(LPCSTR lpszFilePath, DWORD *pdwSize)
{
	char *pData = NULL;
	DWORD dwSize;
	LPSTR pRet = NULL;
	HANDLE hFile = CreateFileA(lpszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	while (hFile != INVALID_HANDLE_VALUE)
	{
		dwSize = GetFileSize(hFile, NULL);
		if (dwSize >= 1024 * 1024 * 100)
		{
			CloseHandle(hFile);
			break;
		}

		pData = (char *)malloc(dwSize + 10);
		if (NULL == pData)
		{
			CloseHandle(hFile);
			break;
		}

		if (!ReadFile(hFile, pData, dwSize, &dwSize, NULL))
		{
			CloseHandle(hFile);
			free(pData);
			break;
		}
		else
		{
			CloseHandle(hFile);
			pData[dwSize] = 0;
			if (pdwSize)
			{
				*pdwSize = dwSize;
			}
			pRet = pData;
			break;
		}
		break;
	}
	return pRet;
}

BOOL __SetFileContent(LPCSTR lpszFilePath, const void *lpData, int iSize)
{
	DWORD dwBytesWritten = 0;
	HANDLE hFile = CreateFileA(lpszFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		WriteFile(hFile, lpData, iSize > 0 ? iSize : strlen((char*)lpData), &dwBytesWritten, NULL);
		CloseHandle(hFile);
	}
	return TRUE;
}

BOOL IsEmptyMemory(char *p, DWORD dwLen)
{
	DWORD i;
	for (i = 0; i < dwLen ; i++)
	{
		if (p[i])
		{
			return FALSE;
		}
	}
	return TRUE;
}

BOOL ReversIAT(char *pOutFileBuf)
{
	PIMAGE_DOS_HEADER       pIDH = (PIMAGE_DOS_HEADER)pOutFileBuf;
	PIMAGE_FILE_HEADER      pIFH = (PIMAGE_FILE_HEADER)(pOutFileBuf + pIDH->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER  pIOH = (PIMAGE_OPTIONAL_HEADER)(pOutFileBuf + pIDH->e_lfanew + 0x18);
	PIMAGE_SECTION_HEADER   pISH = (PIMAGE_SECTION_HEADER)(pOutFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));



	return TRUE;
}

BOOL ReversRebase(char *pOutFileBuf, char *svbase)
{
	PIMAGE_DOS_HEADER       pIDH = (PIMAGE_DOS_HEADER)pOutFileBuf;
	PIMAGE_NT_HEADERS		pNTHeader = (PIMAGE_NT_HEADERS)((char*)pOutFileBuf + pIDH->e_lfanew);
	PIMAGE_FILE_HEADER      pIFH = (PIMAGE_FILE_HEADER)(pOutFileBuf + pIDH->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER  pIOH = (PIMAGE_OPTIONAL_HEADER)(pOutFileBuf + pIDH->e_lfanew + 0x18);
	PIMAGE_SECTION_HEADER   pISH = (PIMAGE_SECTION_HEADER)(pOutFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	
	int i ;
	DWORD *dwRebaseAddr;
	WORD *pRel;
	
	DWORD dwBase = (DWORD)strtoul(svbase, NULL, 16);
	DWORD dwRebaseDelta = (DWORD)(dwBase - pNTHeader->OptionalHeader.ImageBase);
	PIMAGE_DATA_DIRECTORY pRebaseDirectory = (PIMAGE_DATA_DIRECTORY)&pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (pRebaseDirectory->Size > 0)
	{
		PIMAGE_BASE_RELOCATION pImgBaseReloc = (PIMAGE_BASE_RELOCATION)(pOutFileBuf + pRebaseDirectory->VirtualAddress);
		while (pImgBaseReloc->VirtualAddress != 0)
		{
			pRel = (WORD*)((BYTE*)pImgBaseReloc + sizeof(IMAGE_BASE_RELOCATION));
			for (i = 0; i < (int)((pImgBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++)
			{
				if ((pRel[i] >> 12) == IMAGE_REL_BASED_HIGHLOW)
				{
					dwRebaseAddr = (DWORD*)(pOutFileBuf + pImgBaseReloc->VirtualAddress + (pRel[i] & 0xfff));
					*dwRebaseAddr -= dwRebaseDelta;
				}
			}
			pImgBaseReloc = (PIMAGE_BASE_RELOCATION)((char*)pImgBaseReloc + pImgBaseReloc->SizeOfBlock);
		}
	}
	return 0;
}

BOOL ReversFile(char *pRealFileBuf, char *pOutFileBuf)
{
	int i;
	DWORD dwRavMin = 0xFFFFFFFF;
	PIMAGE_DOS_HEADER       pIDH = (PIMAGE_DOS_HEADER)pRealFileBuf;
	PIMAGE_FILE_HEADER      pIFH = (PIMAGE_FILE_HEADER)(pRealFileBuf + pIDH->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER  pIOH = (PIMAGE_OPTIONAL_HEADER)(pRealFileBuf + pIDH->e_lfanew + 0x18);
	PIMAGE_SECTION_HEADER   pISH = (PIMAGE_SECTION_HEADER)(pRealFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));


	for (i = 0; ; i++)
	{
		if (IsEmptyMemory((char *)&pISH[i], sizeof(IMAGE_SECTION_HEADER)))
		{
			break;
		}
		printf("pISH[%d].PointerToRawData = 0x%08X \n", i, pISH[i].PointerToRawData);
		printf("pISH[%d].VirtualAddress = 0x%08X \n", i, pISH[i].VirtualAddress);
		printf("pISH[%d].SizeOfRawData = 0x%08X \n", i, pISH[i].SizeOfRawData);
		printf("\n");
		memmove(pOutFileBuf + pISH[i].PointerToRawData, pRealFileBuf + pISH[i].VirtualAddress, pISH[i].SizeOfRawData);
		if (pISH[i].PointerToRawData < dwRavMin)
		{
			dwRavMin = pISH[i].PointerToRawData;
		}
	}

	memmove(pOutFileBuf, pRealFileBuf, dwRavMin);

	return TRUE;
}

DWORD GetRealFileLen(char *pRealFileBuf)
{
	int i;
	DWORD dwRavMin = 0xFFFFFFFF;
	PIMAGE_DOS_HEADER       pIDH = (PIMAGE_DOS_HEADER)pRealFileBuf;
	PIMAGE_FILE_HEADER      pIFH = (PIMAGE_FILE_HEADER)(pRealFileBuf + pIDH->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER  pIOH = (PIMAGE_OPTIONAL_HEADER)(pRealFileBuf + pIDH->e_lfanew + 0x18);
	PIMAGE_SECTION_HEADER   pISH = (PIMAGE_SECTION_HEADER)(pRealFileBuf + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD dwRaw = 0;
	DWORD dwRawLen = 0;

	for (i = 0; ; i++)
	{
		if (IsEmptyMemory((char *)&pISH[i], sizeof(IMAGE_SECTION_HEADER)))
		{
			break;
		}
		printf("pISH[%d].PointerToRawData = 0x%08X \n", i, pISH[i].PointerToRawData);
		printf("pISH[%d].VirtualAddress = 0x%08X \n", i, pISH[i].VirtualAddress);
		printf("pISH[%d].SizeOfRawData = 0x%08X \n", i, pISH[i].SizeOfRawData);
		printf("\n");
		if (dwRaw < pISH[i].PointerToRawData)
		{
			dwRaw = pISH[i].PointerToRawData;
			dwRawLen = pISH[i].SizeOfRawData;
		}
	}

	return dwRaw + dwRawLen;
}

#if 1


//E:\样本\劫持\4\UK\UK.sys 95C31000
int main(int argc, char **argv)
{
	char *pRealFileBuf;
	char *pOutFileBuf;
	DWORD dwSize = 0;
	char strFile[1024] = "";
	strcpy_s(strFile, sizeof(strFile), argv[1]);

	//	读取文件
	pRealFileBuf = __GetFileContent(strFile, &dwSize);
	if (pRealFileBuf == NULL)
	{
		return 0;
	}

	pOutFileBuf = (char *)malloc(dwSize);
	memset(pOutFileBuf, 0, dwSize);

	if (argc == 3)
	{
		//	修复重定位表
		ReversRebase(pRealFileBuf, argv[2]);
	}

	//	修复导入表
	ReversIAT(pOutFileBuf);

	//	修复文件
	ReversFile(pRealFileBuf, pOutFileBuf);

	//	获取文件长度
	dwSize = GetRealFileLen(pOutFileBuf);

	//	保存文件
	strcat_s(strFile, sizeof(strFile), ".rebuild");
	__SetFileContent(strFile, pOutFileBuf, dwSize);

	free(pOutFileBuf);
	free(pRealFileBuf);
	return 0;
}

#endif
