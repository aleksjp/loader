#ifndef MAIN_H_INC
#define MAIN_H_INC

enum {MAXLEN=512}; /* max length of strings */

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