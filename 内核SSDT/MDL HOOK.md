不通过直接修改SSDT索引表的地址，用MDL的方式hook
```cpp
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

// 内存映射文件
NTSTATUS KernelMapFile(UNICODE_STRING FileName, HANDLE *phFile, HANDLE *phSection, PVOID *ppBaseAddress)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	OBJECT_ATTRIBUTES objectAttr = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	PVOID pBaseAddress = NULL;
	SIZE_T viewSize = 0;

	InitializeObjectAttributes(&objectAttr, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenFile(&hFile, GENERIC_READ, &objectAttr, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0x1000000, hFile);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		return status;
	}

	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress, 0, 1024, 0, &viewSize, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hSection);
		ZwClose(hFile);
		return status;
	}

	// 返回数据
	*phFile = hFile;
	*phSection = hSection;
	*ppBaseAddress = pBaseAddress;

	return status;
}

// 寻找指定函数得到内存地址
ULONG64 GetAddressFromFunction(UNICODE_STRING DllFileName, PCHAR pszFunctionName)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;

	// 内存映射文件
	status = KernelMapFile(DllFileName, &hFile, &hSection, &pBaseAddress);
	if (!NT_SUCCESS(status))
	{
		return 0;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	ULONG ulNumberOfNames = pExportTable->NumberOfNames;
	PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	PCHAR lpName = NULL;

	for (ULONG i = 0; i < ulNumberOfNames; i++)
	{
		lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);
		USHORT uHint = *(USHORT *)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
		ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
		PVOID lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);

		if (_strnicmp(pszFunctionName, lpName, strlen(pszFunctionName)) == 0)
		{
			ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
			ZwClose(hSection);
			ZwClose(hFile);

			return (ULONG64)lpFuncAddr;
		}
	}
	ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
	ZwClose(hSection);
	ZwClose(hFile);
	return 0;
}

// 保存原函数地址
PVOID gOldFunctionAddress = NULL;

// Hook后被替换的新函数
NTSTATUS MyZwOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
)
{
	NTSTATUS status = STATUS_SUCCESS;

	// 定义函数指针
	typedef NTSTATUS(*my_ZwOpenProcess)(
		__out PHANDLE ProcessHandle,
		__in ACCESS_MASK DesiredAccess,
		__in POBJECT_ATTRIBUTES ObjectAttributes,
		__in_opt PCLIENT_ID ClientId
		);

	DbgPrint("执行 MyZwOpenProcess hook \n");

	// 执行原函数
	status = ((my_ZwOpenProcess)gOldFunctionAddress)(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId
		);

	return status;
}

// 挂钩SSDT函数
BOOLEAN SSDTFunctionHook(ULONG64 FunctionAddress)
{
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	ULONG ulNewFuncAddr = 0;

	gOldFunctionAddress = FunctionAddress;

	pMdl = MmCreateMdl(NULL, &FunctionAddress, sizeof(ULONG));
	if (NULL == pMdl)
	{
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);

	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
		return FALSE;
	}
	// 替换hook函数
	ulNewFuncAddr = (ULONG)MyZwOpenProcess;
	RtlCopyMemory(pNewAddress, &ulNewFuncAddr, sizeof(ULONG));
	DbgPrint("myZwOpenProcess内存地址 = %p \n", FunctionAddress);

	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);

	return TRUE;
}

// 恢复SSDT函数
BOOLEAN SSDTFunctionUnHook(ULONG64 FunctionAddress)
{
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	ULONG ulOldFuncAddr = 0;

	gOldFunctionAddress = FunctionAddress;
	
	// 创建MDL映射	
	pMdl = MmCreateMdl(NULL, &FunctionAddress, sizeof(ULONG));
	if (NULL == pMdl)
	{
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);

	// 锁定内存
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
		return FALSE;
	}

	// 写入原函数地址
	ulOldFuncAddr = (ULONG)gOldFunctionAddress;
	RtlCopyMemory(pNewAddress, &ulOldFuncAddr, sizeof(ULONG));

	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);

	return TRUE;
}

// 关闭驱动
VOID UnDriver(PDRIVER_OBJECT driver)
{
	SSDTFunctionUnHook(gOldFunctionAddress);
	DbgPrint("驱动卸载 \n");
}

// 驱动入口
NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;
	UNICODE_STRING FileName = { 0 };
	ULONG64 FunctionAddress = 0;

	RtlInitUnicodeString(&FileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
	status = KernelMapFile(FileName, &hFile, &hSection, &pBaseAddress);
	if (NT_SUCCESS(status))
	{
		DbgPrint("映射到内存地址 = %p \n", pBaseAddress);
	}

	// 获取指定模块导出函数地址
	FunctionAddress = GetAddressFromFunction(FileName, "ZwOpenProcess");
	DbgPrint("ZwOpenProcess内存地址 = %p \n", FunctionAddress);

	if (FunctionAddress != 0)
	{
		BOOLEAN ref = SSDTFunctionHook(FunctionAddress);
		if (ref == TRUE)
		{
			DbgPrint("Hook已挂钩 \n");
		}
	}

	Driver->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}

```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699326531736-24c57aa3-259b-4a90-9fc3-ad04cb38f2cc.png#averageHue=%23e2e2e2&clientId=uad5c0837-cffe-4&from=paste&height=97&id=u2ec6be79&originHeight=116&originWidth=669&originalType=binary&ratio=1.2000000476837158&rotation=0&showTitle=false&size=14149&status=done&style=none&taskId=u394cb7a5-7f93-4e93-a8e6-713fc2d62df&title=&width=557.4999778469412)

