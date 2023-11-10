```c
#include <iostream>
#include <Windows.h>
#include <vector>

#pragma comment(lib,"user32.lib")
#pragma comment(lib,"advapi32.lib")

// 定义驱动功能号和名字，提供接口给应用程序调用
#define IOCTL_IO_MDLStructAll   0x805

class cDrvCtrl
{
public:
	cDrvCtrl()
	{
		m_pSysPath = NULL;
		m_pServiceName = NULL;
		m_pDisplayName = NULL;
		m_hSCManager = NULL;
		m_hService = NULL;
		m_hDriver = INVALID_HANDLE_VALUE;
	}
	~cDrvCtrl()
	{
		CloseServiceHandle(m_hService);
		CloseServiceHandle(m_hSCManager);
		CloseHandle(m_hDriver);
	}

	// 安装驱动
	BOOL Install(PCHAR pSysPath, PCHAR pServiceName, PCHAR pDisplayName)
	{
		m_pSysPath = pSysPath;
		m_pServiceName = pServiceName;
		m_pDisplayName = pDisplayName;
		m_hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (NULL == m_hSCManager)
		{
			m_dwLastError = GetLastError();
			return FALSE;
		}
		m_hService = CreateServiceA(m_hSCManager, m_pServiceName, m_pDisplayName,
			SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
			m_pSysPath, NULL, NULL, NULL, NULL, NULL);
		if (NULL == m_hService)
		{
			m_dwLastError = GetLastError();
			if (ERROR_SERVICE_EXISTS == m_dwLastError)
			{
				m_hService = OpenServiceA(m_hSCManager, m_pServiceName, SERVICE_ALL_ACCESS);
				if (NULL == m_hService)
				{
					CloseServiceHandle(m_hSCManager);
					return FALSE;
				}
			}
			else
			{
				CloseServiceHandle(m_hSCManager);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 启动驱动
	BOOL Start()
	{
		if (!StartServiceA(m_hService, NULL, NULL))
		{
			m_dwLastError = GetLastError();
			return FALSE;
		}
		return TRUE;
	}

	// 关闭驱动
	BOOL Stop()
	{
		SERVICE_STATUS ss;
		GetSvcHandle(m_pServiceName);
		if (!ControlService(m_hService, SERVICE_CONTROL_STOP, &ss))
		{
			m_dwLastError = GetLastError();
			return FALSE;
		}
		return TRUE;
	}

	// 移除驱动
	BOOL Remove()
	{
		GetSvcHandle(m_pServiceName);
		if (!DeleteService(m_hService))
		{
			m_dwLastError = GetLastError();
			return FALSE;
		}
		return TRUE;
	}

	// 打开驱动
	BOOL Open(PCHAR pLinkName)
	{
		if (m_hDriver != INVALID_HANDLE_VALUE)
			return TRUE;
		m_hDriver = CreateFileA(pLinkName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (m_hDriver != INVALID_HANDLE_VALUE)
			return TRUE;
		else
			return FALSE;
	}

	// 发送控制信号
	BOOL IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen, DWORD *RealRetBytes)
	{
		DWORD dw;
		BOOL b = DeviceIoControl(m_hDriver, CTL_CODE_GEN(dwIoCode), InBuff, InBuffLen, OutBuff, OutBuffLen, &dw, NULL);
		if (RealRetBytes)
			*RealRetBytes = dw;
		return b;
	}
private:

	// 获取服务句柄
	BOOL GetSvcHandle(PCHAR pServiceName)
	{
		m_pServiceName = pServiceName;
		m_hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (NULL == m_hSCManager)
		{
			m_dwLastError = GetLastError();
			return FALSE;
		}
		m_hService = OpenServiceA(m_hSCManager, m_pServiceName, SERVICE_ALL_ACCESS);
		if (NULL == m_hService)
		{
			CloseServiceHandle(m_hSCManager);
			return FALSE;
		}
		else
		{
			return TRUE;
		}
	}

	// 获取控制信号对应字符串
	DWORD CTL_CODE_GEN(DWORD lngFunction)
	{
		return (FILE_DEVICE_UNKNOWN * 65536) | (FILE_ANY_ACCESS * 16384) | (lngFunction * 4) | METHOD_BUFFERED;
	}

public:
	DWORD m_dwLastError;
	PCHAR m_pSysPath;
	PCHAR m_pServiceName;
	PCHAR m_pDisplayName;
	HANDLE m_hDriver;
	SC_HANDLE m_hSCManager;
	SC_HANDLE m_hService;
};

void GetAppPath(char *szCurFile)
{
	GetModuleFileNameA(0, szCurFile, MAX_PATH);
	for (SIZE_T i = strlen(szCurFile) - 1; i >= 0; i--)
	{
		if (szCurFile[i] == '\\')
		{
			szCurFile[i + 1] = '\0';
			break;
		}
	}
}

// MDL数据传递变量
typedef struct
{
	char username[256];
	char password[256];
	int count;
}StructAll;

int main(int argc, char *argv[])
{
	cDrvCtrl DriveControl;

	// 设置驱动名称
	char szSysFile[MAX_PATH] = { 0 };
	char szSvcLnkName[] = "aaa";;
	GetAppPath(szSysFile);
	strcat_s(szSysFile, "aaa.sys");

	// 安装并启动驱动
	DriveControl.Install(szSysFile, szSvcLnkName, szSvcLnkName);
	DriveControl.Start();

	// 打开驱动的符号链接
	DriveControl.Open((PCHAR)("\\\\.\\aaa"));

	// 直接输出循环结构体
	StructAll *ptr;
	// 派遣命令
	DriveControl.IoControl(IOCTL_IO_MDLStructAll, 0, 0, &ptr, sizeof(PVOID), 0);

	long size = ptr[0].count;
	printf("共享内存地址: %x \n", ptr);
	std::cout << "得到结构体总数: " << size << std::endl;
	for (int x = 0; x < size; x++)
	{
		std::cout << "计数器: " << x << std::endl;
		std::cout << "用户名: " << ptr[x].username << std::endl;
		std::cout << "密码: " << ptr[x].password << std::endl;
		std::cout << std::endl;
	}

	// 关闭符号链接句柄
	CloseHandle(DriveControl.m_hDriver);

	// 停止并卸载驱动
	DriveControl.Stop();
	DriveControl.Remove();

	system("pause");
	return 0;
}
```
```c
#include <ntifs.h>
#include <windef.h>


#define DEVICE_NAME        L"\\Device\\aaa"
#define LINK_NAME          L"\\DosDevices\\aaa"
#define LINK_GLOBAL_NAME   L"\\DosDevices\\Global\\aaa"
#define FILE_DEVICE_EXTENSION 4096

// 定义驱动功能号和名字，提供接口给应用程序调用
#define IOCTL_IO_MDLStructAll   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 定义传递结构体
typedef struct
{
	int uuid;
	char szUname[1024];
}MyData;

// MDL数据传递变量
typedef struct
{
	char username[256];
	char password[256];
	int count;
}StructAll;
static StructAll ptr[1024] = { 0 };

// 模拟进程列表赋值
int ShowProcess(int process_count)
{
	memset(ptr, 0, sizeof(StructAll) * process_count);
	
	int x = 0;
	for (; x < process_count + 1; x++)
	{
		strcpy_s(ptr[x].username, 256, "hello");
		strcpy_s(ptr[x].password, 256, "123456");
	}

	ptr[0].count = x;
	return x;
}

// 默认派遣函数
NTSTATUS DefaultDispatch(PDEVICE_OBJECT _pDeviceObject, PIRP _pIrp)
{
	_pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	_pIrp->IoStatus.Information = 0;
	IoCompleteRequest(_pIrp, IO_NO_INCREMENT);
	return _pIrp->IoStatus.Status;
}

// 卸载例程
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	if (pDriverObj->DeviceObject)
	{
		UNICODE_STRING strLink;

		RtlInitUnicodeString(&strLink, LINK_NAME);
		IoDeleteSymbolicLink(&strLink);
		IoDeleteDevice(pDriverObj->DeviceObject);
		DbgPrint("驱动已卸载 \n");
	}
}

// IRP_MJ_CREATE 
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("驱动处理例程载入 \n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IRP_MJ_CLOSE 
NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("关闭派遣 \n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IRP_MJ_DEVICE_CONTROL
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInSize;
	ULONG uOutSize;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (uIoControlCode)
	{
		// 测试MDL传输多次结构体
	case IOCTL_IO_MDLStructAll:
	{
		// 模拟获取到当前列表数据
		int count = ShowProcess(100);
		long pool_size = sizeof(MyData) * count;
		DbgPrint("总进程数: %d  分配内存池大小: %d \n", count, pool_size);

		__try
		{
			// 分配内核空间
			PVOID pShareMM_SYS = ExAllocatePool(NonPagedPool, pool_size);
			RtlZeroMemory(pShareMM_SYS, pool_size);

			// 创建MDL映射
			PMDL pShareMM_MDL = IoAllocateMdl(pShareMM_SYS, pool_size, FALSE, FALSE, NULL);
			MmBuildMdlForNonPagedPool(pShareMM_MDL);
			// 将内核空间映射到用户空间
			PVOID pShareMM_User = MmMapLockedPagesSpecifyCache(pShareMM_MDL, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
			DbgPrint("用户地址空间: 0x%x \n", pShareMM_User);
			DbgPrint("内核地址空间: 0x%p \n", pShareMM_SYS);

			// 拷贝数据到内核空间
			RtlCopyMemory(pShareMM_SYS, &ptr, sizeof(ptr[0]) * count);

			// 将用户空间指针返回给应用层
			pIrp->AssociatedIrp.SystemBuffer = pShareMM_User;	

		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}
		status = STATUS_SUCCESS;
		break;
	}
	}

	if (status == STATUS_SUCCESS)
	{
		pIrp->IoStatus.Information = uOutSize;
	}
	else
	{
		pIrp->IoStatus.Information = 0;
	}

	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

// 驱动的初始化工作
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	PDEVICE_OBJECT pDevObj;

	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DbgPrint("初始化派遣: %d \n", i);
		pDriverObj->MajorFunction[i] = DefaultDispatch;
	}
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;

	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	status = IoCreateDevice(pDriverObj, sizeof(FILE_DEVICE_EXTENSION), &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (IoIsWdmVersionAvailable(1, 0x10))
	{
		RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
	}
	else
	{
		RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	}
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("创建符号链接失败 \n");
		IoDeleteDevice(pDevObj);
		return status;
	}

	return STATUS_SUCCESS;
}

```
