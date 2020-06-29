#pragma warning(disable: 4996)
#include<windows.h>
#include<TLHELP32.H>
#include<iostream>
using std::cout;
using std::endl;

DWORD process_to_pid(char*process_name);
DWORD inject_module_to_process_by_pid(DWORD process_pid,char*dll_full_path);

int main(int argc, char*argv[]) {
	char* process_name = "HostProc.exe";
	char* dll_full_path = "MsgDll.dll";

	DWORD dw_pid = process_to_pid(process_name);
	if (dw_pid == 0) {
		cout << "δ�ҵ�Ŀ�����" << endl;
		return 0;
	}

	cout << "Ŀ�����pid��" << dw_pid << endl;
	BOOL result = inject_module_to_process_by_pid(dw_pid, dll_full_path);
	cout << "�����" << result << endl;
	return 0;
}

DWORD inject_module_to_process_by_pid(DWORD process_pid, char*dll_full_path) {
	SIZE_T st_size = 0;
	BOOL b_status = FALSE;
	LPVOID lp_data = NULL;
	SIZE_T path_len = lstrlen(dll_full_path) + 1;

	HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_pid);
	if (h_process) {
		//����ռ�
		lp_data = VirtualAllocEx(h_process, NULL, path_len, MEM_COMMIT, PAGE_READWRITE);
		if (lp_data) {
			b_status = WriteProcessMemory(h_process,lp_data,dll_full_path,path_len,&st_size);
		}
		else {
			cout << "�ռ����ʧ�ܣ�������룺" << GetLastError() << endl;
			return FALSE;
		}
		CloseHandle(h_process);
	}

	if (b_status == FALSE) {
		cout << "��ȡDLL�����ַ���ʧ�ܣ�������룺" << GetLastError() << endl;
		return FALSE;
	}

	//�����߳̿���
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	HANDLE thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (thread_snap == INVALID_HANDLE_VALUE) {
		cout << "�߳̿��ջ�ȡʧ�ܣ�������룺" << GetLastError() << endl;
		return FALSE;
	}
	//��ȡ�����̣߳����������߳����APC
	if (Thread32First(thread_snap, &te32)) {
		do{
			if (te32.th32OwnerProcessID == process_pid) {//�жϵ�ǰ�߳��Ƿ�����Ŀ�����
				HANDLE h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
				if (h_thread) {
					//���߳�����û�̬APC��LoadLibraryA(dll_full_path)
					DWORD dw_ret = QueueUserAPC((PAPCFUNC)LoadLibraryA, h_thread, (ULONG_PTR)lp_data);
					if (dw_ret > 0)
						b_status = TRUE;
					CloseHandle(h_thread);
				}
			}
		} while (Thread32Next(thread_snap, &te32));
	}

	CloseHandle(thread_snap);
	return b_status;
}

DWORD process_to_pid(char*process_name) {
	HANDLE process_snap = NULL;
	DWORD process_pid = 0;
	PROCESSENTRY32 pe32 = { 0 };//��Ž��̿��գ�Process32Nextָ����һ��������Ϣ
	process_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//�򿪽����б�
	if (process_snap == (HANDLE)-1) {
		cout << "���̿��մ���ʧ�ܣ������룺" << GetLastError() << endl;
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	if (Process32First(process_snap, &pe32)) {
		do {
			if (!stricmp(process_name, pe32.szExeFile)) {
				process_pid = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(process_snap, &pe32));
	}
	else {
		cout << "��ȡ��һ�����̾��ʧ�ܣ�������룺" << GetLastError() << endl;
		return FALSE;
	}
	CloseHandle(process_snap);
	return process_pid;
}