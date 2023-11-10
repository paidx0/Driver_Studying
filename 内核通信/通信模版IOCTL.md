```cpp
#define _CRT_SECURE_NO_WARNINGS
#include <ntifs.h>
#include <windef.h>

// 定义符号链接
#define DEVICE_NAME        L"\\Device\\driver_demo"
#define LINK_NAME          L"\\DosDevices\\driver_demo"
#define LINK_GLOBAL_NAME   L"\\DosDevices\\Global\\driver_demo"

// 定义驱动功能号和名字，提供接口给应用程序调用
#define IOCTL_IO_Msg            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_TEST           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 保存一段非分页内存,用于给全局变量使用
#define FILE_DEVICE_EXTENSION 4096

// 定义传递结构体
typedef struct
{
	int uuid;
	char szUname[1024];
}MyData;

// 驱动绑定默认派遣函数
NTSTATUS DefaultDispatch(PDEVICE_OBJECT _pDeviceObject, PIRP _pIrp)
{
	_pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	_pIrp->IoStatus.Information = 0;
	IoCompleteRequest(_pIrp, IO_NO_INCREMENT);
	return _pIrp->IoStatus.Status;
}

// 驱动卸载的处理例程
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	if (pDriverObj->DeviceObject)
	{
		UNICODE_STRING strLink;

		// 删除符号连接和设备
		RtlInitUnicodeString(&strLink, LINK_NAME);
		IoDeleteSymbolicLink(&strLink);
		IoDeleteDevice(pDriverObj->DeviceObject);
		DbgPrint("驱动已卸载 \n");
	}
}

// 驱动载入的处理例程
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("驱动处理例程载入 \n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// 驱动关闭的处理例程
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
	// 获取控制码
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	// 输入和输出的缓冲区
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	// 发送传入数据的BUFFER长度
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	// 接收传出数据的BUFFER长度
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	// 对不同控制信号的处理流程
	switch (uIoControlCode)
	{
	case IOCTL_IO_Msg:
	{
		DbgPrint("aaa\n");
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_IO_TEST:
	{
		DWORD dw = 0;
		memcpy(&dw, pIoBuffer, sizeof(DWORD));
		dw++;
		memcpy(pIoBuffer, &dw, sizeof(DWORD));
		status = STATUS_SUCCESS;
		break;
	}

	// 设定DeviceIoControl的*lpBytesReturned的值
	if (status == STATUS_SUCCESS)
	{
		pIrp->IoStatus.Information = uOutSize;
	}
	else
	{
		pIrp->IoStatus.Information = 0;
	}

	// 设定DeviceIoControl的返回值是成功还是失败
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	PDEVICE_OBJECT pDevObj;

	 
	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
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

	// 判断支持的WDM版本
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

	DbgPrint("驱动初始化完毕 \n");
	return status;
}

```
```cpp
#include <iostream>
#include <Windows.h>
#include <vector>

#pragma comment(lib,"user32.lib")
#pragma comment(lib,"advapi32.lib")

// 定义驱动功能号和名字，提供接口给应用程序调用
#define IOCTL_IO_Msg            0x800
#define IOCTL_IO_TEST           0x801


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


typedef struct
{
	int uuid;
	char szUname[1024];
}MyData;

int main(int argc, char *argv[])
{
	cDrvCtrl DriveControl;

	// 设置驱动名称
	char szSysFile[MAX_PATH] = { 0 };
	char szSvcLnkName[] = "driver_demo";;
	GetAppPath(szSysFile);
	strcat(szSysFile, "driver_demo.sys");

	// 安装并启动驱动
	DriveControl.Install(szSysFile, szSvcLnkName, szSvcLnkName);
	DriveControl.Start();

	// 打开驱动的符号链接
	DriveControl.Open("\\\\.\\driver_demo");

	// 无参数输出
	DriveControl.IoControl(IOCTL_IO_Msg, 0, 0, 0, 0, 0);

	// 传入x参数,返回到y中,返回长度为z
	DWORD input = 100, output = 0, ref_len = 0;
	DriveControl.IoControl(IOCTL_IO_TEST, &input, sizeof(input), &output, sizeof(output), &ref_len);
	std::cout << "传入参数: " << input << std::endl;
	std::cout << "输出参数: " << output << std::endl;
	std::cout << "参数长度: " << ref_len << std::endl;


	// 关闭符号链接句柄
	CloseHandle(DriveControl.m_hDriver);

	// 停止并卸载驱动
	DriveControl.Stop();
	DriveControl.Remove();

	system("pause");
	return 0;
}

```
