通过 rdmsr(c0000082)读取MSR寄存器得到 nt!KiSystemCall64，计算 nt!KiSystemCall64和nt!KiSystemServiceUser的偏移量<br />得到 nt!KiSystemServiceUser = rdmsr(c0000082) - 偏移量<br />向下找到 nt!KiSystemServiceRepeat，里面就是 SSDT和SSSDT表地址<br />![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699197696354-6240e25c-2b31-4e4f-8d00-914ff4174732.png#averageHue=%23e6e2e2&clientId=ufe62cfea-0eb4-4&from=paste&height=298&id=u85b1f1c6&originHeight=298&originWidth=582&originalType=binary&ratio=1&rotation=0&showTitle=false&size=12945&status=done&style=none&taskId=ub84a5c71-8237-4e98-827a-4112a722a97&title=&width=582)<br />![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699197803178-99e7e65f-5cda-4486-91a6-0788130f4177.png#averageHue=%23e4e4e4&clientId=ufe62cfea-0eb4-4&from=paste&height=90&id=u40814be4&originHeight=90&originWidth=737&originalType=binary&ratio=1&rotation=0&showTitle=false&size=5182&status=done&style=none&taskId=u1d6b8128-0974-4b0b-b9a1-70adc17f708&title=&width=737)
```c
#include <ntifs.h>

ULONGLONG ssdt_address = 0;

// 获取 KeServiceDescriptorTable 首地址
ULONGLONG GetLySharkCOMKeServiceDescriptorTable()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082) - 0x202;
	// 设置结束位置
	PUCHAR EndSearchAddress = StartSearchAddress + 0x100000;

	PUCHAR ByteCode;
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
			特征值寻找 nt!KeServiceDescriptorTable 函数地址
			nt!KiSystemServiceRepeat:
			fffff800`03ef2a72 4c8d1587be1f00  lea     r10,[nt!KeServiceDescriptorTable (fffff800`040ee900)]
			fffff800`03ef2a79 4c8d1d40bf1f00  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff800`040ee9c0)]
			*/
			if (OpCodeA == 0x4c && OpCodeB == 0x8d && OpCodeC == 0x15)
			{
				memcpy(&templong, ByteCode + 3, 4);

				addr = (ULONGLONG)templong + (ULONGLONG)ByteCode + 7;
				return addr;
			}
		}
	}
	return  0;
}

VOID UnDriver(PDRIVER_OBJECT driver)
{
	DbgPrint(("驱动程序卸载成功! \n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	ssdt_address = GetLySharkCOMKeServiceDescriptorTable();
	DbgPrint("SSDT = %p \n", ssdt_address);

	DriverObject->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}

```
