```cpp
#include <ntifs.h>

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

VOID UnDriver(PDRIVER_OBJECT driver)
{
	DbgPrint(("Uninstall Driver Is OK \n"));
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
	Driver->DriverUnload = UnDriver;

	PLDR_DATA_TABLE_ENTRY pLdr = NULL;
	PLIST_ENTRY pListEntry = NULL;
	PLIST_ENTRY pCurrentListEntry = NULL;
	PLDR_DATA_TABLE_ENTRY pCurrentModule = NULL;
	pLdr = (PLDR_DATA_TABLE_ENTRY)Driver->DriverSection;
	pListEntry = pLdr->InLoadOrderLinks.Flink;
	pCurrentListEntry = pListEntry->Flink;


	while (pCurrentListEntry != pListEntry)
	{
		// 获取LDR_DATA_TABLE_ENTRY结构
		pCurrentModule = CONTAINING_RECORD(pCurrentListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (pCurrentModule->BaseDllName.Buffer != 0)
		{
			DbgPrint("模块名 = %wZ | 模块基址 = %p | 模块入口 = %p | 模块时间戳 = %d \n",
				pCurrentModule->BaseDllName,
				pCurrentModule->DllBase,
				pCurrentModule->EntryPoint,
				pCurrentModule->TimeDateStamp);
		}
		pCurrentListEntry = pCurrentListEntry->Flink;
	}

	return STATUS_SUCCESS;
}

```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699000463558-2f24e29e-e974-4646-9db3-db9690370ee9.png#averageHue=%23d8d8d7&clientId=u154fa597-147a-4&from=paste&height=263&id=u5eb936e9&originHeight=395&originWidth=640&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=47345&status=done&style=none&taskId=ud2dc524a-fbfc-4d3f-b239-4c91346b27e&title=&width=426.6666666666667)
