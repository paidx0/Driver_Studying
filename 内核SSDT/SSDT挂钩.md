SSDT系统服务描述符表，将R3和R0之间的API函数连接起来，SSDT不仅是一个庞大的地址索引表，还有服务函数个数和基址<br />通过修改SSDT的函数地址可以对Windows的API函数进行HOOK，实现过滤和监控
```c
#include <windows.h>

int main(int argc, char* argv[])
{
	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 2548);
	return 0;
}

```
OD找到OpenProcess，<br />![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699114080347-cc4fc872-0bd3-4da5-8fed-0460e37a3034.png#averageHue=%231a1614&clientId=u6d63dcf7-926a-4&from=paste&height=115&id=u81ba4b82&originHeight=115&originWidth=722&originalType=binary&ratio=1&rotation=0&showTitle=false&size=5767&status=done&style=none&taskId=uae72418e-1cf5-4b3c-b3fb-2631dce6518&title=&width=722)<br />F7进去，找到ntdll.NtOpenProcess，<br />![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699114244161-60c99f55-bd23-4290-9d01-d48894b33bbc.png#averageHue=%23141310&clientId=u6d63dcf7-926a-4&from=paste&height=118&id=uae9e57c7&originHeight=118&originWidth=739&originalType=binary&ratio=1&rotation=0&showTitle=false&size=5611&status=done&style=none&taskId=u8a613a92-36d2-492c-9488-ec28c7e96b0&title=&width=739)<br />跟进去，传了个0x23，也就是35<br />![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699114553270-f8c0d059-2432-4b4b-8b83-58039016ce2e.png#averageHue=%23e5e500&clientId=u6d63dcf7-926a-4&from=paste&height=77&id=u784a9576&originHeight=77&originWidth=488&originalType=binary&ratio=1&rotation=0&showTitle=false&size=2650&status=done&style=none&taskId=u497cad0d-cc24-454d-a805-c9cbe97a710&title=&width=488)<br />在SSDT表中正好对应NtOpenProcess<br />![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699114599987-770f70d1-a53e-4a9d-867d-6be8b523c4f8.png#averageHue=%23eccc81&clientId=u6d63dcf7-926a-4&from=paste&height=143&id=u1a02f8ca&originHeight=143&originWidth=813&originalType=binary&ratio=1&rotation=0&showTitle=false&size=26710&status=done&style=none&taskId=u23b47265-1471-47f6-8cbf-7fb9a959752&title=&width=813)<br />后面交给ntoskrnl.exe进入到R0层调用<br />进入用户层：kernel32 ( OpenProcess) -> ntdll(NTOpenProcess)->ntdll(SyaEnter)<br />进入内核层：ntoskrnl.exe (nt ! ZW0penProcess) -> ntoskrnl.exe(nt!KiSystemService) ->ntoskrnl.exe (nt! NtOpenProccess)<br />![](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699115263734-0a47bcf2-301c-404d-9ac3-59603392c960.png#averageHue=%23f9dfdf&clientId=u6d63dcf7-926a-4&from=paste&id=u2905370d&originHeight=515&originWidth=1044&originalType=url&ratio=1&rotation=0&showTitle=false&status=done&style=none&taskId=udad655a4-fd4d-48e0-978e-1351aed0052&title=)
```c
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    KSYSTEM_SERVICE_TABLE ntoskrnl; // ntoskrnl.exe 的服务函数
    KSYSTEM_SERVICE_TABLE win32k; // win32k.sys 的服务函数 (GDI32.dll/User32.dll 的内核支持)
    KSYSTEM_SERVICE_TABLE notUsed1;
    KSYSTEM_SERVICE_TABLE notUsed2;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

其中，KSYSTEM_SERVICE_TABLE结构体定义如下：

typedef struct _KSYSTEM_SERVICE_TABLE
{
    PULONG  ServiceTableBase; // SSDT的基地址
    PULONG  ServiceCounterTableBase; // SSDT中每个服务被调用的次数
    ULONG   NumberOfService; // 服务函数的索引个数,32位系统中每个地址长度4个字节，NumberOfService * 4 就是整个地址表的大小
    ULONG   ParamTableBase; // SSPT的基地址
} KSYSTEM_SERVICE_TABLE, *PKSYSTEM_SERVICE_TABLE;
```
计算某个函数的偏移量<br />KeServiceDescriptorTable->serviceTableBase +函数ID * 4

0x191也就是401，当前系统SSDT中索引函数有401个<br />![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699117298841-e308ecd4-e576-4b1f-9054-3ef50fb33a96.png#averageHue=%23d9d9d8&clientId=u6d63dcf7-926a-4&from=paste&height=152&id=u5dda353e&originHeight=152&originWidth=457&originalType=binary&ratio=1&rotation=0&showTitle=false&size=6595&status=done&style=none&taskId=u86b71bc8-7630-4faa-b83f-f62c56393e5&title=&width=457)<br />![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699117346606-1b640d37-7380-47ea-826e-80e410f83cf8.png#averageHue=%23e8cb81&clientId=u6d63dcf7-926a-4&from=paste&height=67&id=u84b40f84&originHeight=67&originWidth=223&originalType=binary&ratio=1&rotation=0&showTitle=false&size=3941&status=done&style=none&taskId=u7c5b46e7-999c-4b3b-b133-e5e01eab546&title=&width=223)
```c
#include <ntddk.h>

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG  NumberOfService;
	PUCHAR ParamTableBase;
}SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TALBE;
PSERVICE_DESCRIPTOR_TALBE KeServiceDescriptorTable;


typedef NTSTATUS(*NtOpenProcessEx)(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK AccessMask,
	IN PVOID ObjectAttributes,
	IN PCLIENT_ID Clientld
);
NtOpenProcessEx ulNtOpenProcessEx = NULL;// 存放原始函数地址
ULONG ulNtOpenProcessExAddr = 0;         // SSDT函数地址索引指针


// 页面只读关闭
VOID MmEnableWP()
{
	SIZE_T cr0 = (SIZE_T)__readcr0();
	cr0 |= 0x10000;
	__writecr0(cr0);
}
// 页面只读打开
VOID MmDisableWP()
{
	SIZE_T cr0 = (SIZE_T)__readcr0();
	cr0 &= ~((SIZE_T)1 << 16);
	__writecr0(cr0);
}

// HOOK函数
NTSTATUS MyNtOpenProcessEx(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK AccessMask,
	IN PVOID ObjectAttributes,
	IN PCLIENT_ID Clientld)
{
	DbgPrint("执行我自己的驱动函数\n");
	NTSTATUS Status = STATUS_SUCCESS;
	// 执行原来函数
	Status = ulNtOpenProcessEx(
		ProcessHandle,
		AccessMask,
		ObjectAttributes,
		Clientld
	);
	return Status;
}

VOID HookOpenProcess()
{
	ULONG ulSsdt = 0;
	ulSsdt = (ULONG)KeServiceDescriptorTable->ServiceTableBase;          // 读取到SSDT表的基地址
	ulNtOpenProcessExAddr = ulSsdt + 0x23 * 4;                           // 索引到指定的函数
	ulNtOpenProcessEx = (NtOpenProcessEx)*(PULONG)ulNtOpenProcessExAddr; // 存储原始函数地址
	MmEnableWP();													     // 关闭只读保护
	*(PULONG)ulNtOpenProcessExAddr = (ULONG)MyNtOpenProcessEx;           // 将新函数地址HOOK
	MmDisableWP();                                                       // 开启只读保护
}

void SSDTHookUnload(IN PDRIVER_OBJECT DriverObject)
{
	MmEnableWP();
	*(PULONG)ulNtOpenProcessExAddr = (ULONG)ulNtOpenProcessEx;
	MmDisableWP();
	DbgPrint("驱动卸载完成 !\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	DbgPrint("驱动加载完成 !\n");
	DriverObject->DriverUnload = SSDTHookUnload;
	
	HookOpenProcess();
	return STATUS_SUCCESS;
}


```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699163961148-2efee081-8fa0-43aa-8dde-d3268610c9e7.png#averageHue=%23efeeed&clientId=u6d63dcf7-926a-4&from=paste&height=283&id=u8b7cbbd1&originHeight=283&originWidth=600&originalType=binary&ratio=1&rotation=0&showTitle=false&size=64281&status=done&style=none&taskId=u47742981-0c84-4248-86c6-ab16fd497c5&title=&width=600)

