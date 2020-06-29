/*-----------------------------------------------------------------------
Reference from 《加密与解密（第四版）》 第12章  注入技术
使用CreateRemoteThread往进程中注入：LoadLibraryA("DllName")
-----------------------------------------------------------------------*/
#include<iostream>
#include<windows.h>
#include<tlhelp32.h>

using std::cout;

BOOL WINAPI InjectDllToProcess(DWORD dwTargetPid, LPCTSTR DllPath);//use CreateRemoteThread to dll inject
DWORD ProcesstoPid(char *Processname);//get process pid
BOOL EnableDebugPrivilege();//set debug proviliege

int main(int argc,char* argv[]) {

	char*szProcName = new char[MAX_PATH];
	char*szDllPath = new char[MAX_PATH];

	if (argc != 3) {
		szProcName = "HostProc.exe";
		szDllPath = "MsgDll.dll";
	}
	else {
		szProcName = argv[1];
		char*szDllPath = argv[2];
	}

	DWORD dwPid = ProcesstoPid(szProcName);
	EnableDebugPrivilege();
	InjectDllToProcess(dwPid, szDllPath);
	return 0;
}

BOOL WINAPI InjectDllToProcess(DWORD dwTargetPid, LPCTSTR DllPath) {


	HANDLE hProc = NULL;
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetPid);//获取PROCESS_ALL_ACCESS权限，没有继承的handle

	if (hProc == NULL) {
		cout << "打开目标进程失败!\n";
		return FALSE;
	}

	LPTSTR psLibFileRemote = NULL;

	//开辟buffer存放DLL名称
	psLibFileRemote = (LPSTR)VirtualAllocEx(hProc, NULL, lstrlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);//使用MEM_COMMIT表示分配物理空间，PAGE_READWRITE用于在页中读写数据

	if (psLibFileRemote == NULL) {
		cout << "页分配失败！\n";
		return FALSE;
	}

	//使用WriteProcessMemory函数将DLL的路径名复制到远程的内存空间
	if (WriteProcessMemory(hProc, psLibFileRemote, (void*)DllPath, lstrlen(DllPath) + 1, NULL) == 0) {//判断页可写
		cout << "页无法写入数据\n";
		return FALSE;
	}

	//获取LoadLibraryA地址
	PTHREAD_START_ROUTINE pfnStartAddr = NULL;
	pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");

	if (pfnStartAddr == NULL) {
		cout << "获取LoadLibraryA地址失败！\n";
		return FALSE;	
	}

	//创建线程，线程内容为LoadLibraryA(psLibFileRemote)
	HANDLE hThread = NULL;
	hThread = CreateRemoteThread(hProc, NULL, 0, pfnStartAddr, psLibFileRemote, 0, NULL);

	if (hThread == NULL) {
		cout << "线程创建失败！\n";
		return FALSE;
	}

	cout << "DLL注入成功！\n"
		<<"DLL "<<DllPath<<" 注入进程 "<<dwTargetPid<<"\n";

	return TRUE;
}

DWORD ProcesstoPid(char*Processname) {
	HANDLE hProcessSnap = NULL;
	DWORD ProcessId = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //打开进程快照
	if (hProcessSnap == (HANDLE)-1){
		printf("\nCreateToolhelp32Snapshot() Error: %d", GetLastError());
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnap, &pe32)) //开始枚举进程
	{
		do
		{
			if (!stricmp(Processname, pe32.szExeFile)) //判断是否和提供的进程名相等，是，返回进程的ID
			{
				ProcessId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32)); //继续枚举进程
	}
	else
	{
		printf("\nProcess32First() Error: %d", GetLastError());
		return 0;
	}
	CloseHandle(hProcessSnap); //关闭系统进程快照的句柄
	return ProcessId;
}

BOOL EnableDebugPrivilege() {
	TOKEN_PRIVILEGES tkp;
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {//打开当前进程失败 
		return FALSE; 
	}

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid); //查看当前权限
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); //调整权限，如上设置
	return TRUE;
}