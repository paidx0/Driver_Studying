```c
#include <ntifs.h>
#pragma intrinsic(__readmsr)

typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID          ServiceTableBase;
	PVOID          ServiceCounterTableBase;
	ULONGLONG      NumberOfServices;
	PVOID          ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

PSYSTEM_SERVICE_TABLE KeServiceDescriptorTableShadow = 0;
ULONG64 ul64W32pServiceTable = 0;

// 获取 KeServiceDescriptorTableShadow 首地址
ULONGLONG GetKeServiceDescriptorTableShadow()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082) - 0x202;
	// 设置结束位置
	PUCHAR EndSearchAddress = StartSearchAddress + 0x100000;

	PUCHAR ByteCode = NULL;
	UCHAR OpCodeA = 0, OpCodeB = 0, OpCodeC = 0;
	ULONGLONG addr = 0;
	ULONG templong = 0;

	for (ByteCode = StartSearchAddress; ByteCode < EndSearchAddress; ByteCode++)
	{
		if (MmIsAddressValid(ByteCode) && MmIsAddressValid(ByteCode + 1) && MmIsAddressValid(ByteCode + 2))
		{
			OpCodeA = *ByteCode;
			OpCodeB = *(ByteCode + 1);
			OpCodeC = *(ByteCode + 2);

			/*
			特征值寻找 nt!KeServiceDescriptorTableShadow 函数地址
			nt!KiSystemServiceRepeat:
			fffff800`03ef2a72 4c8d1587be1f00  lea     r10,[nt!KeServiceDescriptorTable (fffff800`040ee900)]
			fffff800`03ef2a79 4c8d1d40bf1f00  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff800`040ee9c0)]
			*/
			if (OpCodeA == 0x4c && OpCodeB == 0x8d && OpCodeC == 0x1d)
			{
				memcpy(&templong, ByteCode + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)ByteCode + 7;
				return addr;
			}
		}
	}
	return  0;
}

// 得到SSSDT个数
ULONGLONG GetSSSDTCount()
{
	PSYSTEM_SERVICE_TABLE pWin32k;
	ULONGLONG W32pServiceTable;

	pWin32k = (PSYSTEM_SERVICE_TABLE)((ULONG64)KeServiceDescriptorTableShadow + sizeof(SYSTEM_SERVICE_TABLE));
	W32pServiceTable = (ULONGLONG)(pWin32k->ServiceTableBase);
	// DbgPrint("Count => %d \n", pWin32k->NumberOfServices);

	return pWin32k->NumberOfServices;
}

VOID UnDriver(PDRIVER_OBJECT driver)
{
	DbgPrint(("驱动程序卸载成功! \n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	KeServiceDescriptorTableShadow = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTableShadow();
	DbgPrint("SSSDT基地址 = 0x%p \n", KeServiceDescriptorTableShadow);

	ULONGLONG count = GetSSSDTCount();
	DbgPrint("SSSDT个数 = %d \n", count);

	// 循环枚举SSSDT
	for (size_t Index = 0; Index < count; Index++)
	{
		PSYSTEM_SERVICE_TABLE pWin32k;
		ULONGLONG W32pServiceTable;

		pWin32k = (PSYSTEM_SERVICE_TABLE)((ULONG64)KeServiceDescriptorTableShadow + sizeof(SYSTEM_SERVICE_TABLE));
		W32pServiceTable = (ULONGLONG)(pWin32k->ServiceTableBase);

		// 获取SSSDT地址
		//ln win32k!W32pServiceTable+((poi(win32k!W32pServiceTable+4*(1-1000))&0x00000000`ffffffff)>>4)-10000000
		//u win32k!W32pServiceTable+((poi(win32k!W32pServiceTable+4*(Index-0x1000))&0x00000000`ffffffff)>>4)-0x10000000

		//u poi(win32k!W32pServiceTable+4*(1-0x1000))
		//u poi(win32k!W32pServiceTable+4*(1-0x1000))&0x00000000`ffffffff
		//u (poi(win32k!W32pServiceTable+4*(1-0x1000))&0x00000000`ffffffff)>>4

		//u win32k!W32pServiceTable+((poi(win32k!W32pServiceTable+4*(1-0x1000))&0x00000000`ffffffff)>>4)-0x10000000

		ULONGLONG qword_temp = 0;
		LONG dw = 0;

		// SSSDT 下标从1000开始，而W32pServiceTable是从0开始
		// + 4 则是每次向下4字节就是下一个地址
		qword_temp = W32pServiceTable + 4 * (Index - 0x1000);

		dw = *(PLONG)qword_temp;
		// dw = qword_temp & 0x00000000ffffffff;
		dw = dw >> 4;
		qword_temp = W32pServiceTable + (LONG64)dw;

		DbgPrint("ID: %d | SSSDT: 0x%p \n", Index, qword_temp);
	}

	DriverObject->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}

```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699200279893-4e712ab3-c1f1-40e5-8179-b5c861d589bd.png#averageHue=%23dadada&clientId=ubead6376-5280-4&from=paste&height=206&id=u3ac5e833&originHeight=206&originWidth=264&originalType=binary&ratio=1&rotation=0&showTitle=false&size=5242&status=done&style=none&taskId=uc634aeb5-c713-4a48-9ce9-8597a9fbdc4&title=&width=264)
