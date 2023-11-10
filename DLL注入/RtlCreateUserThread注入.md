RtlCreateUserThread是createRemoteThread的底层实现，zwCreateThread实现注入

```c
#include "my_data.h"

typedef struct _ReadMemoryStruct
{
	ULONG pid;
	DWORD size;
	DWORD64 address;
	PVOID data;
}ReadMemoryStruct;

// 定义函数指针
typedef PVOID(NTAPI* PfnRtlCreateUserThread)
(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT size_t StackReserved,
	IN OUT size_t StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientID
	);

PVOID GetProcessAddress(HANDLE ProcessID, PWCHAR DllName, PCCHAR FunctionName)
{
	PEPROCESS EProcess = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	KAPC_STATE ApcState;
	PVOID RefAddress = 0;

	Status = PsLookupProcessByProcessId(ProcessID, &EProcess);
	if (Status != STATUS_SUCCESS)
	{
		return Status;
	}

	BOOLEAN IsWow64 = (PsGetProcessWow64Process(EProcess) != NULL) ? TRUE : FALSE;
	if (!MmIsAddressValid(EProcess))
	{
		return NULL;
	}
	KeStackAttachProcess((PRKPROCESS)EProcess, &ApcState);
	__try
	{
		UNICODE_STRING DllUnicodeString = { 0 };
		PVOID BaseAddress = NULL;
		RtlInitUnicodeString(&DllUnicodeString, DllName);

		BaseAddress = GetUserModuleAddress(EProcess, &DllUnicodeString, IsWow64);
		if (!BaseAddress)
		{
			return NULL;
		}
		DbgPrint("模块基址: %p \n", BaseAddress);
		RefAddress = GetModuleExportAddress(BaseAddress, FunctionName, EProcess);
		DbgPrint("函数地址: %p \n", RefAddress);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}

	KeUnstackDetachProcess(&ApcState);
	return RefAddress;
}

// 远程线程注入函数
BOOLEAN MyCreateRemoteThread(ULONG pid, PVOID pRing3Address, PVOID PParam)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE ApcState = { 0 };

	PfnRtlCreateUserThread RtlCreateUserThread = NULL;
	HANDLE hThread = 0;

	__try
	{
		UNICODE_STRING ustrRtlCreateUserThread;
		RtlInitUnicodeString(&ustrRtlCreateUserThread, L"RtlCreateUserThread");
		RtlCreateUserThread = (PfnRtlCreateUserThread)MmGetSystemRoutineAddress(&ustrRtlCreateUserThread);
		if (RtlCreateUserThread == NULL)
		{
			return FALSE;
		}

		status = PsLookupProcessByProcessId((HANDLE)pid, &pEProcess);
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}

		KeStackAttachProcess(pEProcess, &ApcState);
		if (!MmIsAddressValid(pRing3Address))
		{
			return FALSE;
		}

		status = RtlCreateUserThread(ZwCurrentProcess(),
			NULL,
			FALSE,
			0,
			0,
			0,
			pRing3Address,
			PParam,
			&hThread,
			NULL);
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}

		return TRUE;
	}

	__finally
	{
		if (pEProcess != NULL)
		{
			ObDereferenceObject(pEProcess);
			pEProcess = NULL;
		}
		KeUnstackDetachProcess(&ApcState);
	}

	return FALSE;
}

VOID Unload(PDRIVER_OBJECT pDriverObj)
{
	DbgPrint("[-] 驱动卸载 \n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	ULONG process_id = 5200;
	DWORD create_size = 1024;
	DWORD64 ref_address = 0;

	PVOID pLoadLibraryW = GetProcessAddress(process_id, L"kernel32.dll", "LoadLibraryW");
	DbgPrint("所在内存地址 = %p \n", pLoadLibraryW);

	NTSTATUS Status = AllocMemory(process_id, create_size, &ref_address);
	DbgPrint("分配的内核堆基址: %p \n", ref_address);

	// 转换为多字节
	UCHAR DllPath[256] = "C:\\hook.dll";
	UCHAR Item[256] = { 0 };
	for (int x = 0, y = 0; x < strlen(DllPath) * 2; x += 2, y++)
	{
		Item[x] = DllPath[y];
	}

	// 写出数据到内存
	ReadMemoryStruct ptr;
	ptr.pid = process_id;
	ptr.address = ref_address;
	ptr.size = strlen(DllPath) * 2;
	ptr.data = ExAllocatePool(PagedPool, ptr.size);
	for (int i = 0; i < ptr.size; i++)
	{
		ptr.data[i] = Item[i];
	}
	MDLWriteMemory(&ptr);

	// 执行线程注入
	BOOLEAN flag = MyCreateRemoteThread(process_id, pLoadLibraryW, ref_address);
	if (flag == TRUE)
	{
		DbgPrint("已完成进程 %d 注入文件 %s \n", process_id, DllPath);
	}

	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}

```
