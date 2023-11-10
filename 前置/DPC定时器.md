```cpp
#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>

LONG count = 0;
KTIMER g_ktimer;
KDPC g_kdpc;


VOID MyTimerProcess(__in struct _KDPC *Dpc, __in_opt PVOID DeferredContext, __in_opt PVOID SystemArgument1, __in_opt PVOID SystemArgument2)
{
	LARGE_INTEGER la_dutime = { 0 };
	la_dutime.QuadPart = 1000 * 1000 * -10;

	// 递增计数器
	InterlockedIncrement(&count);
	DbgPrint("DPC 定时执行 = %d \n", count);

	// 再次设置定时
	KeSetTimer(&g_ktimer, la_dutime, &g_kdpc);
}

VOID UnDriver(PDRIVER_OBJECT driver)
{
	// 取消计数器
	KeCancelTimer(&g_ktimer);

	DbgPrint(("Uninstall Driver Is OK \n"));
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
	LARGE_INTEGER la_dutime = { 0 };

	// 每隔1秒执行一次
	la_dutime.QuadPart = 1000 * 1000 * -10;

	KeInitializeTimer(&g_ktimer);
	KeInitializeDpc(&g_kdpc, MyTimerProcess, NULL);
	// 只会触发一次DPC例程
	KeSetTimer(&g_ktimer, la_dutime, &g_kdpc);

	Driver->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}

```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699001380798-66c20bbb-4fed-4901-bbea-eed1179ceced.png#averageHue=%23efeeee&clientId=ua5126349-7bf9-4&from=paste&height=171&id=u227b6871&originHeight=256&originWidth=515&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=16990&status=done&style=none&taskId=ub3f9148f-29ba-4ccc-b28a-0e22af9d5eb&title=&width=343.3333333333333)
