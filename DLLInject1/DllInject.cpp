/*-----------------------------------------------------------------------
Reference from ����������ܣ����İ棩�� ��12��  ע�뼼��
ʹ��CreateRemoteThread��������ע�룺LoadLibraryA("DllName")
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
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetPid);//��ȡPROCESS_ALL_ACCESSȨ�ޣ�û�м̳е�handle

	if (hProc == NULL) {
		cout << "��Ŀ�����ʧ��!\n";
		return FALSE;
	}

	LPTSTR psLibFileRemote = NULL;

	//����buffer���DLL����
	psLibFileRemote = (LPSTR)VirtualAllocEx(hProc, NULL, lstrlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);//ʹ��MEM_COMMIT��ʾ��������ռ䣬PAGE_READWRITE������ҳ�ж�д����

	if (psLibFileRemote == NULL) {
		cout << "ҳ����ʧ�ܣ�\n";
		return FALSE;
	}

	//ʹ��WriteProcessMemory������DLL��·�������Ƶ�Զ�̵��ڴ�ռ�
	if (WriteProcessMemory(hProc, psLibFileRemote, (void*)DllPath, lstrlen(DllPath) + 1, NULL) == 0) {//�ж�ҳ��д
		cout << "ҳ�޷�д������\n";
		return FALSE;
	}

	//��ȡLoadLibraryA��ַ
	PTHREAD_START_ROUTINE pfnStartAddr = NULL;
	pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");

	if (pfnStartAddr == NULL) {
		cout << "��ȡLoadLibraryA��ַʧ�ܣ�\n";
		return FALSE;	
	}

	//�����̣߳��߳�����ΪLoadLibraryA(psLibFileRemote)
	HANDLE hThread = NULL;
	hThread = CreateRemoteThread(hProc, NULL, 0, pfnStartAddr, psLibFileRemote, 0, NULL);

	if (hThread == NULL) {
		cout << "�̴߳���ʧ�ܣ�\n";
		return FALSE;
	}

	cout << "DLLע��ɹ���\n"
		<<"DLL "<<DllPath<<" ע����� "<<dwTargetPid<<"\n";

	return TRUE;
}

DWORD ProcesstoPid(char*Processname) {
	HANDLE hProcessSnap = NULL;
	DWORD ProcessId = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //�򿪽��̿���
	if (hProcessSnap == (HANDLE)-1){
		printf("\nCreateToolhelp32Snapshot() Error: %d", GetLastError());
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnap, &pe32)) //��ʼö�ٽ���
	{
		do
		{
			if (!stricmp(Processname, pe32.szExeFile)) //�ж��Ƿ���ṩ�Ľ�������ȣ��ǣ����ؽ��̵�ID
			{
				ProcessId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32)); //����ö�ٽ���
	}
	else
	{
		printf("\nProcess32First() Error: %d", GetLastError());
		return 0;
	}
	CloseHandle(hProcessSnap); //�ر�ϵͳ���̿��յľ��
	return ProcessId;
}

BOOL EnableDebugPrivilege() {
	TOKEN_PRIVILEGES tkp;
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {//�򿪵�ǰ����ʧ�� 
		return FALSE; 
	}

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid); //�鿴��ǰȨ��
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); //����Ȩ�ޣ���������
	return TRUE;
}