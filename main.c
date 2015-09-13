// (c) Alexandar, 2015 alexjptr@gmail.com
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "main.h"
#include "resource.h"

#pragma warning(suppress: 28251)
int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	int ret;
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nShowCmd);
	/* integer types and enum types can be freely assigned to each other */
	ret=LoadFrom(EXE_NAME, DLL_NAME);
	return ret=bOk(ret);
}

/**************************************************
*   LoadFrom                                      *
*   The return value is an integer constant.     *
*   0 on successful completion, 1 to 10 otherwise *
*   Type:  Basefn                                 *
***************************************************/
Basefn LoadFrom(const wchar_t *pszExe, const wchar_t *pszLib )
{

	wchar_t szExePath[MAX_PATH]= { 0 };
	wchar_t szLibFile[MAX_PATH]= { 0 };

	STARTUPINFO sinfo= { 0 };
	PROCESS_INFORMATION pinfo;

	Basefn ret=RET_OK; // Exit status
	HMODULE hModule; // kernel32 module handle
	LPVOID pMem=NULL; // Allocated library string and command line parameters
	DWORD cbLen=0;    // Library string length
	DWORD dwWriten;   // Number of written bytes
	DWORD dwExitCode; // Remote thread exit code
	HANDLE hProcess=NULL; // Process handle
	HANDLE hThread=NULL; // Remote thread handle
	PTHREAD_START_ROUTINE pfnThread; // LoadLibraryW address

	// Get the current directory and append name of executable
	if(GetCurrentDirectory(MAX_PATH, szExePath))
	{
		wcscat_s(szExePath, MAX_PATH, L"\\");
		wcscat_s(szExePath, MAX_PATH, pszExe);
	}

	// Check for a file existence
	if((GetFileAttributes(szExePath) == INVALID_FILE_ATTRIBUTES))
	{
#ifdef _DEBUG
		DTRACE(L"File Not Found!", L"Could not find %s \nMake sure that it actually exists, and try again.", pszExe);
#endif
		ret=RET_ERROR_FILE;
		goto end;
	}

/*
   That is if we need to create a new directory and file inside it.
   We can override this preprocessor definition from compiler command line using /DBUILD_BIK flag
*/
#ifdef BUILD_BIK

	if(GetCurrentDirectory(MAX_PATH, szLibFile))
		wcscat_s(szLibFile, MAX_PATH, L"\\devraw\\video");

	if(!DirectoryExists(szLibFile))
	{
		if(!CreateDirs(szLibFile))
		{
#ifdef _DEBUG
			DTRACE(L"Directoy not found!", L"Could not create %s\nlast-error error 0x%x\n", szLibFile, GetLastError());
#endif
			ret=RET_ERROR_DIRECTORY;
			goto end;
		}
	}

	wcscat_s(szLibFile, MAX_PATH, L"\\startup.bik");
	if(!FileExist(szLibFile))
	{
		if(!ExtractFromResource(IDR_BIN1, L"BIN", szLibFile))
		{
#ifdef _DEBUG
			DTRACE(L"Extract data Error!", L"Could not extarct data\nlast-error 0x%x\n", GetLastError());
#endif
			ret=RET_ERROR_RESOURCE;
			goto end;
		}
	}

#endif

	// Build a full path to DLL file
	if(GetCurrentDirectory(MAX_PATH, szLibFile))
		swprintf_s(szLibFile, ARRAY_LEN(szLibFile), L"%s\\%s", szLibFile, pszLib);

	// Extract DLL from resource and write to a file
	if(!ExtractFromResource(IDR_BIN2, L"BIN", szLibFile))
	{
#ifdef _DEBUG
		DTRACE(L"Extract Dll Error!", L"Could not extract data\nlast-error 0x%x\n", GetLastError());
#endif
		ret=RET_ERROR_RESOURCE;
		goto end;
	}

	// Initialize/reset struct to 0
	memset(&sinfo, 0, sizeof(sinfo));
	memset(&pinfo, 0, sizeof(pinfo));
	
	sinfo.cb = sizeof(sinfo);

	// Create procces in suspended state
	if(!CreateProcess(szExePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sinfo, &pinfo))
	{
#ifdef _DEBUG
		DTRACE(L"CreateProcess!", L"CreateProcess failed\nlast-error 0x%x\n", GetLastError());
#endif
		ret=RET_ERROR_CREATE;
		goto end;
	}

	// Calculate size needed for the DLL pathname
	cbLen = (wcslen(szLibFile) + 1) * sizeof(wchar_t);

	// Allocate space in the remote process for the DLL pathname
	pMem = VirtualAllocEx(pinfo.hProcess, NULL, cbLen, MEM_COMMIT, PAGE_READWRITE);
	if(pMem == NULL)
	{
#ifdef _DEBUG
		DTRACE(L"VirtualAllocEx", L"Could not allocate memory for the DLL string\nlast-error 0x%x\n", GetLastError());
#endif
		ret=RET_ERROR_VALLOC;
		goto end;
	}

	// Copy the DLL pathname to the remote process address space
	if(!WriteProcessMemory(pinfo.hProcess, pMem, szLibFile, cbLen, &dwWriten))
	{
#ifdef _DEBUG
		DTRACE(L"WriteProcessMemory", L"Could not write remote string\nlast-error 0x%x\n", GetLastError());
#endif
		ret=RET_ERROR_WRITE;
		goto end;
	}

	// Get the real address of LoadLibraryW in Kernel32.dll
	hModule=GetModuleHandle(L"Kernel32");
	if(!hModule)
	{
#ifdef _DEBUG
		DTRACE(L"GetModuleHandle", L"Could not retrieve DLL handle\nlast-error 0x%x\n", GetLastError());
#endif
		ret=RET_ERROR_MODULE;
		goto end;
	}
	pfnThread = (PTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryW");
	if(pfnThread == NULL)
	{
#ifdef _DEBUG
		DTRACE(L"GetProcAddress", L"Could not find address of LoadLibraryW\nlast-error 0x%x\n", GetLastError());
#endif
		ret=RET_ERROR_GETPROCADDR;
		goto end;
	}

	// Create remote thread that calls LoadLibraryW
	hThread = CreateRemoteThread(pinfo.hProcess, NULL, 0, pfnThread, pMem, 0, NULL);
	if(hThread == NULL)
	{
#ifdef _DEBUG
		DTRACE(L"CreateRemoteThread", L"Could not start remote thread\nlast-error 0x%x\n", GetLastError());

#endif
		ret=RET_ERROR_CREATERTHREAD;
		goto end;
	}

	// Wait for the remote thread to terminate
	WaitForSingleObject(hThread, INFINITE);
	if(!GetExitCodeThread(hThread, &dwExitCode))
	{
#ifdef _DEBUG
		DTRACE(L"GetExitCodeThread", L"GetExitCodeThread failed\nlast-error 0x%x\n", GetLastError());
#endif
		ret=RET_ERROR_UNKNOWN;
		goto end;
	}
    
	// Free the remote memory that contained dll pathname
	if(pMem != NULL)
		VirtualFreeEx(pinfo.hProcess, pMem, 0, MEM_RELEASE);

	if(hThread != NULL)
	{
		// Resume base process thread
		ResumeThread(pinfo.hThread);

		// Clean everything else up
		CloseHandle(pinfo.hThread);
		CloseHandle(pinfo.hProcess);
		CloseHandle(hThread);
	}

end:

	return ret;
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


/****************************************************************
*  CreateDirs                                                   *
*  Returns true on success directory creation, false otherwise. *
*  Type:  BOOL                                                  *
****************************************************************/
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
					// Get the size of resource in bytes
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
								return bRet; // success
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
