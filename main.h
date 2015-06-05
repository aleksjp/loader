#ifndef MAIN_H_INC
#define MAIN_H_INC

/* Function prototipes */
BOOL DirectoryExists(const wchar_t *szPath);
BOOL FileExist(const wchar_t *szFile);
BOOL CreateDir(const wchar_t *szPath);
BOOL ExtractFromResource(int ResID, LPCWSTR ResType, LPCWSTR FileName);

#endif /* MAIN_H_INC */