#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "main.h"
#include "resource.h"

#define BUILD_BIK

#define EXE_NAME L"iw5mp.exe"
#define DLL_NAME L"steam_api.dll"

int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{

	wchar_t szExePath[MAX_PATH]= { 0 };
	wchar_t szLibFile[MAX_PATH]= { 0 };

	STARTUPINFO sinfo= { 0 };
	PROCESS_INFORMATION pinfo= { 0 };
	LPVOID pMem=NULL;
	DWORD cbLen=0;
	DWORD dwWriten;
	HANDLE hProcess=NULL;
	HANDLE hThread=NULL;
	PTHREAD_START_ROUTINE pfnThread;

	// Get the current directory and append name of executable
	if(GetCurrentDirectory(MAX_PATH, szExePath))
	{
		wcscat_s(szExePath, MAX_PATH, L"\\");
		wcscat_s(szExePath, MAX_PATH, EXE_NAME);
	}

	// Check for a file existence
	if((GetFileAttributes(szExePath) == INVALID_FILE_ATTRIBUTES))
	{
#ifdef _DEBUG
		DTRACE(L"File Not Found!", L"Could not find " EXE_NAME L"\nMake sure that it actually exists, and try again.");
#endif
		return 1;
	}

#ifdef BUILD_BIK

	if(GetCurrentDirectory(MAX_PATH, szLibFile))
		wcscat_s(szLibFile, MAX_PATH, L"\\devraw\\video");

	if(!DirectoryExists(szLibFile))
	{
		if(!CreateDirs(szLibFile))
		{
#ifdef _DEBUG
			DTRACE(L"Directoy not found!", L"Could not create %s error 0x%x\n", szLibFile, GetLastError());
#endif
			return 1;
		}
	}

	wcscat_s(szLibFile, MAX_PATH, L"\\startup.bik");
	if(!FileExist(szLibFile))
	{
		if(!ExtractFromResource(IDR_BIN1, L"BIN", szLibFile))
		{
#ifdef _DEBUG
			DTRACE(L"Extract data Error!", L"Could not extarct data error 0x%x\n", GetLastError());
#endif
			return 1;
		}
	}

#endif

	// Build a full path to DLL file
	if(GetCurrentDirectory(MAX_PATH, szLibFile))
		swprintf_s(szLibFile, ARRAY_LEN(szLibFile), L"%s\\%s", szLibFile, DLL_NAME);

	// Extract DLL from resource and write to a file
	if(!ExtractFromResource(IDR_BIN2, L"BIN", szLibFile))
	{
#ifdef _DEBUG
		DTRACE(L"Extract Dll Error!", L"Could not extract data error 0x%x\n", GetLastError());
#endif
		return 1;
	}

	// Initialize/reset struct to 0
	memset(&sinfo, 0, sizeof(sinfo));
	memset(&pinfo, 0, sizeof(pinfo));
	sinfo.cb = sizeof(sinfo);

	// Create procces in suspended state
	if(FAILED(CreateProcess(szExePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sinfo, &pinfo)))
	{
#ifdef _DEBUG
		DMSG(CreateProcess Failed!, CreateProcess);
#endif
		return 1;
	}

	// Calculate size needed for the DLL pathname
	cbLen = (wcslen(szLibFile) + 1) * sizeof(wchar_t);

	// Allocate space in the remote process for the DLL pathname
	pMem = VirtualAllocEx(pinfo.hProcess, NULL, cbLen, MEM_COMMIT, PAGE_READWRITE);
	if(pMem == NULL)
	{
#ifdef _DEBUG
		DMSG(Could not allocate memory for the DLL string!, VirtualAllocEx);
#endif
		return 1;
	}

	// Copy the DLL pathname to the remote process address space
	if(!WriteProcessMemory(pinfo.hProcess, pMem, szLibFile, cbLen, &dwWriten))
	{
#ifdef _DEBUG
		DMSG(Could not write remote string!, WriteProcessMemory);
#endif
		return 1;
	}

	// Get the real address of LoadLibraryW in Kernel32.dll
	pfnThread = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryW");
	if(pfnThread == NULL)
	{
#ifdef _DEBUG
		DMSG(Could not find address of LoadLibraryW!, GetProcAddress);
#endif
		return 1;
	}

	// Create remote thread that calls LoadLibraryW
	hThread = CreateRemoteThread(pinfo.hProcess, NULL, 0, pfnThread, pMem, 0, NULL);
	if(hThread == NULL)
	{
#ifdef _DEBUG
		DMSG(Could not start remote thread!, CreateRemoteThread);
#endif
		return 1;
	}

	// Wait for the remote thread to terminate
	WaitForSingleObject(hThread, INFINITE);


	// Free the remote memory that contained dll pathname
	if(pMem != NULL)
		VirtualFreeEx(pinfo.hProcess, pMem, 0, MEM_RELEASE);

	if(hThread != NULL)
		CloseHandle(hThread);

	// Resume base process thread
	ResumeThread(pinfo.hThread);

	// Clean everything else up
	CloseHandle(pinfo.hThread);
	CloseHandle(pinfo.hProcess);

	return 0;
}

/*********************************************************
*  DirectoryExists                                       *
*  Returns true if the directory exist, false otherwise. *
*  Type:  BOOL                                           *
*********************************************************/
BOOL DirectoryExists(const wchar_t* szPath)
{
	DWORD dwAttrib=GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

/*********************************************************
*  FileExist                                             *
*  Returns true if the file exist, false otherwise.      *
*  Type:  BOOL                                           *
*********************************************************/
BOOL FileExist(const wchar_t* szFile)
{
	struct _stat buffer;
	return (_wstat(szFile, &buffer) == 0);
}


/*********************************************************
*  CreateDirs                                            *
*  Returns true on success, false otherwise.             *
*  Type:  BOOL                                           *
*********************************************************/
BOOL CreateDirs(const wchar_t* szPath)
{
	wchar_t DirName[MAX_PATH]= { 0 };
	wchar_t* p;
	wchar_t* q;

	if(szPath == NULL)
		return FALSE;
	for(p = (wchar_t*)szPath, q = DirName; *p != L'\0'; p++)
	{
		if(*(p - 1) != L':' && ((*p == L'\\') || (*p == L'/')))
		{
			if(!DirectoryExists(DirName))
				if(!CreateDirectoryW(DirName, NULL))
					return FALSE;
		}
		*q++ = *p;
		*q = L'\0';
	}

	return (CreateDirectoryW(DirName, NULL));
}

/*********************************************************
*  ExtractFromResource                                   *
*  Returns true on success, false otherwise.             *
*  Type:  BOOL                                           *
*********************************************************/
BOOL ExtractFromResource(int ResID, const wchar_t* ResType, const wchar_t* FileName)
{

	HANDLE hFile=INVALID_HANDLE_VALUE;
	HMODULE hMod=GetModuleHandle(NULL);
	DWORD WriteOut=0;
	DWORD RsrcSize=0;
	HRSRC hRes=NULL;
	HGLOBAL hResMem=NULL;
	LPVOID pResData=NULL;
	BOOL bRet=FALSE;

	__try
	{
		hRes = FindResource(hMod, MAKEINTRESOURCE(ResID), ResType);
		if(hRes != NULL)
		{
			// Load the resource into memory
			hResMem = LoadResource(hMod, hRes);
			if(hResMem != NULL)
			{
				// Lock the resource into global memory
				pResData = LockResource(hResMem);
				if(pResData != NULL)
				{
					//Get the size of resource in bytes
					RsrcSize = SizeofResource(hMod, hRes);
					if(RsrcSize != 0)
					{
						hFile = CreateFileW(FileName, GENERIC_WRITE, 0, NULL,\
						                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
						if(hFile != INVALID_HANDLE_VALUE)
						{
							// Writes data to the file
							bRet = WriteFile(hFile, pResData, RsrcSize, &WriteOut, NULL);
							if(bRet && (RsrcSize == WriteOut))
							{
								// Clean up resource
								FreeResource(hResMem);
								CloseHandle(hFile);
							}
						}

					}

				}

			}

		}

	}

	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		// Exception handling block
#ifdef _DEBUG
		DTRACE(L"Exception raised", L"Exception is 0x%x\n", GetExceptionCode());
#endif
		FreeResource(hResMem);
		CloseHandle(hFile);
		/* ExitProcess(1); */
	}

	return bRet;
}

/*********************************************************
*  DTRACE                                                *
*  Returns formated strings to MessageBox.               *
*  Type:  int                                            *
*********************************************************/
int DTRACE(const wchar_t* caption, const wchar_t* FmtMsg, ...)
{
	wchar_t buffer[MAXLEN]= { 0 };
	va_list va;

	va_start(va, FmtMsg);
	_vsnwprintf_s(buffer, ARRAY_LEN(buffer), _TRUNCATE, FmtMsg, va);
	va_end(va);

	return MessageBox(NULL, buffer, caption, MB_OK);
}
