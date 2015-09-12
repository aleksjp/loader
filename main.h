#ifndef MAIN_H_INC
#define MAIN_H_INC

/* constants */

#define EXE_NAME L"iw5mp.exe"
#define DLL_NAME L"steam_api.dll"

enum{MAXLEN=512}; /* max length of strings */

/* return type error definition and macro to check the exit statuss */
typedef enum _BaseErr
{
	RET_OK = 0,
	RET_ERROR_FILE,
	RET_ERROR_DIRECTORY,
	RET_ERROR_RESOURCE,
	RET_ERROR_CREATE,
	RET_ERROR_VALLOC,
	RET_ERROR_WRITE,
	RET_ERROR_MODULE,
	RET_ERROR_GETPROCADDR,
	RET_ERROR_CREATERTHREAD,
	RET_ERROR_UNKNOWN
} BaseErr;

#define bOk(ret) (ret > 0 && ret < 11)

/* simple MessageBox macro for debugging purpose */
#define DMSG(A, B) { MessageBox(NULL, L#A, L#B, MB_ICONINFORMATION | MB_OK); }

/* array length macro from Google's Chromium project */
#define ARRAY_LEN(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

/* Function prototipes */
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

BOOL DirectoryExists(const wchar_t *szPath);
BOOL FileExist(const wchar_t *szFile);
BOOL CreateDirs(const wchar_t *szPath);
BOOL ExtractFromResource(int ResID, const wchar_t *ResType, const wchar_t *FileName);
int DTRACE(const wchar_t *FmtMsg, const wchar_t *caption, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MAIN_H_INC */
