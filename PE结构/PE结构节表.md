```cpp
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    USHORT      Magic;
    UCHAR       MajorLinkerVersion;
    UCHAR       MinorLinkerVersion;
    ULONG       SizeOfCode;                 // 所有包含代码节的总大小
    ULONG       SizeOfInitializedData;      // 已初始化的节
    ULONG       SizeOfUninitializedData;    // 未初始化的节
    ULONG       AddressOfEntryPoint;        // 程序执行入口RVA 
    ULONG       BaseOfCode;                 // 代码节起始RVA
    ULONGLONG   ImageBase;                  // 程序镜像基地址
    ULONG       SectionAlignment;           // 
    ULONG       FileAlignment;              //
    USHORT      MajorOperatingSystemVersion;//
    USHORT      MinorOperatingSystemVersion;//
    USHORT      MajorImageVersion;          //
    USHORT      MinorImageVersion;
    USHORT      MajorSubsystemVersion;
    USHORT      MinorSubsystemVersion;
    ULONG       Win32VersionValue;
    ULONG       SizeOfImage;                // 内存中整个PE映像大小
    ULONG       SizeOfHeaders;              // 头节表大小
    ULONG       CheckSum;
    USHORT      Subsystem;
    USHORT      DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    ULONG       LoaderFlags;
    ULONG       NumberOfRvaAndSizes;
    // 数据目录的结构数量
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```
```cpp
typedef struct _IMAGE_SECTION_HEADER {
    UCHAR   Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            ULONG   PhysicalAddress;
            ULONG   VirtualSize;
    } Misc;
    ULONG   VirtualAddress;         // 节区RVA
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   PointerToRelocations;
    ULONG   PointerToLinenumbers;
    USHORT  NumberOfRelocations;
    USHORT  NumberOfLinenumbers;
    ULONG   Characteristics;        // 节区属性
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```
![](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699321546474-d5f94632-f894-41b9-8525-aba46908f5c6.png#averageHue=%23f0f0f0&clientId=u317a5911-6445-4&from=paste&id=u67ab972c&originHeight=500&originWidth=1000&originalType=url&ratio=1.2000000476837158&rotation=0&showTitle=false&status=done&style=none&taskId=ue602187a-61c0-426b-a412-82df42fc72d&title=)
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

VOID UnDriver(PDRIVER_OBJECT driver)
{
	DbgPrint("驱动卸载 \n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;
	UNICODE_STRING FileName = { 0 };

	RtlInitUnicodeString(&FileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
	status = KernelMapFile(FileName, &hFile, &hSection, &pBaseAddress);
	if (!NT_SUCCESS(status))
	{
		return 0;
	}

	// 获取PE头数据集
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = &pNtHeaders->FileHeader;

	DbgPrint("运行平台:     %x\n", pFileHeader->Machine);
	DbgPrint("节区数目:     %x\n", pFileHeader->NumberOfSections);
	DbgPrint("时间标记:     %x\n", pFileHeader->TimeDateStamp);
	DbgPrint("可选头大小    %x\n", pFileHeader->SizeOfOptionalHeader);
	DbgPrint("文件特性:     %x\n", pFileHeader->Characteristics);
	DbgPrint("入口点：        %p\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	DbgPrint("镜像基址：      %p\n", pNtHeaders->OptionalHeader.ImageBase);
	DbgPrint("镜像大小：      %p\n", pNtHeaders->OptionalHeader.SizeOfImage);
	DbgPrint("代码基址：      %p\n", pNtHeaders->OptionalHeader.BaseOfCode);
	DbgPrint("区块对齐：      %p\n", pNtHeaders->OptionalHeader.SectionAlignment);
	DbgPrint("文件块对齐：    %p\n", pNtHeaders->OptionalHeader.FileAlignment);
	DbgPrint("子系统：        %x\n", pNtHeaders->OptionalHeader.Subsystem);
	DbgPrint("区段数目：      %d\n", pNtHeaders->FileHeader.NumberOfSections);
	DbgPrint("时间日期标志：  %x\n", pNtHeaders->FileHeader.TimeDateStamp);
	DbgPrint("首部大小：      %x\n", pNtHeaders->OptionalHeader.SizeOfHeaders);
	DbgPrint("特征值：        %x\n", pNtHeaders->FileHeader.Characteristics);
	DbgPrint("校验和：        %x\n", pNtHeaders->OptionalHeader.CheckSum);
	DbgPrint("可选头部大小：  %x\n", pNtHeaders->FileHeader.SizeOfOptionalHeader);
	DbgPrint("RVA 数及大小：  %x\n", pNtHeaders->OptionalHeader.NumberOfRvaAndSizes);

	ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
	ZwClose(hSection);
	ZwClose(hFile);

	Driver->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}

```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699322433850-a7cb7ee6-e6eb-4bc7-b000-dc4745cd517c.png#averageHue=%23e6e6e6&clientId=u317a5911-6445-4&from=paste&height=347&id=u349da08f&originHeight=417&originWidth=590&originalType=binary&ratio=1.2000000476837158&rotation=0&showTitle=false&size=58465&status=done&style=none&taskId=uff81bda4-750b-48b3-81d2-546d09e8647&title=&width=491.6666471295894)
```cpp
NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;
	UNICODE_STRING FileName = { 0 };

	RtlInitUnicodeString(&FileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
	status = KernelMapFile(FileName, &hFile, &hSection, &pBaseAddress);
	if (!NT_SUCCESS(status))
	{
		return 0;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
	PIMAGE_FILE_HEADER pFileHeader = &pNtHeaders->FileHeader;
	// 获取区块数量
	DWORD NumberOfSectinsCount = 0;
	NumberOfSectinsCount = pFileHeader->NumberOfSections;

	DWORD64 *difA = NULL;   // 虚拟地址开头
	DWORD64 *difS = NULL;   // 相对偏移(用于遍历)

	difA = ExAllocatePool(NonPagedPool, NumberOfSectinsCount * sizeof(DWORD64));
	difS = ExAllocatePool(NonPagedPool, NumberOfSectinsCount * sizeof(DWORD64));

	DbgPrint("节区名称 相对偏移\t虚拟大小\tRaw数据指针\tRaw数据大小\t节区属性\n");

	for (DWORD temp = 0; temp < NumberOfSectinsCount; temp++, pSection++)
	{
		DbgPrint("%10s\t 0x%x \t 0x%x \t 0x%x \t 0x%x \t 0x%x \n",
			pSection->Name, pSection->VirtualAddress, pSection->Misc.VirtualSize,
			pSection->PointerToRawData, pSection->SizeOfRawData, pSection->Characteristics);

		difA[temp] = pSection->VirtualAddress;
		difS[temp] = pSection->VirtualAddress - pSection->PointerToRawData;
	}

	ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
	ZwClose(hSection);
	ZwClose(hFile);

	Driver->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}

```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699323086095-6af291aa-5987-4b0b-b4b9-7a38d2e207e3.png#averageHue=%23e2e2e2&clientId=u317a5911-6445-4&from=paste&height=141&id=u6ba75182&originHeight=169&originWidth=867&originalType=binary&ratio=1.2000000476837158&rotation=0&showTitle=false&size=24938&status=done&style=none&taskId=ud1b2e810-7fa2-418b-a903-c96d494a7f3&title=&width=722.4999712904306)
