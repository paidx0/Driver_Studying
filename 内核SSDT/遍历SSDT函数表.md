```c
#include <ntifs.h>

typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID     ServiceTableBase;
	PVOID     ServiceCounterTableBase;
	ULONGLONG   NumberOfServices;
	PVOID     ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

ULONGLONG ssdt_base_aadress;
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

typedef UINT64(__fastcall *SCFN)(UINT64, UINT64);
SCFN scfn;


VOID DecodeSSDT()
{
	UCHAR strShellCode[36] = "\x48\x8B\xC1\x4C\x8D\x12\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x4E\x8B\x14\x17\x4D\x63\x1C\x82\x49\x8B\xC3\x49\xC1\xFB\x04\x4D\x03\xD3\x49\x8B\xC2\xC3";
	/*
	48:8BC1                  | mov rax,rcx                             |  rcx=index
	4C:8D12                  | lea r10,qword ptr ds:[rdx]              |  rdx=ssdt
	8BF8                     | mov edi,eax                             |
	C1EF 07                  | shr edi,7                               |
	83E7 20                  | and edi,20                              |
	4E:8B1417                | mov r10,qword ptr ds:[rdi+r10]          |
	4D:631C82                | movsxd r11,dword ptr ds:[r10+rax*4]     |
	49:8BC3                  | mov rax,r11                             |
	49:C1FB 04               | sar r11,4                               |
	4D:03D3                  | add r10,r11                             |
	49:8BC2                  | mov rax,r10                             |
	C3                       | ret                                     |
	*/
	scfn = ExAllocatePool(NonPagedPool, 36);
	memcpy(scfn, strShellCode, 36);
}

// 获取 KeServiceDescriptorTable 首地址
ULONGLONG GetKeServiceDescriptorTable()
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

// 得到函数相对偏移地址
ULONG GetOffsetAddress(ULONGLONG FuncAddr)
{
	ULONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	if (KeServiceDescriptorTable == NULL)
	{
		KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTable();
	}
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = (ULONG)(FuncAddr - (ULONGLONG)ServiceTableBase);
	return dwtmp << 4;
}

// 根据序号得到函数地址
ULONGLONG GetSSDTFunctionAddress(ULONGLONG NtApiIndex)
{
	ULONGLONG ret = 0;
	if (ssdt_base_aadress == 0)
	{
		ssdt_base_aadress = GetKeServiceDescriptorTable();
	}
	if (scfn == NULL)
	{
		DecodeSSDT();
	}
	ret = scfn(NtApiIndex, ssdt_base_aadress);
	return ret;
}

// 查询函数系统地址
ULONG_PTR QueryFunctionSystemAddress(PWCHAR name)
{
	UNICODE_STRING na;
	ULONG_PTR address;
	RtlInitUnicodeString(&na, name);
	address = (ULONG_PTR)MmGetSystemRoutineAddress(&na);
	return address;
}

VOID UnDriver(PDRIVER_OBJECT driver)
{
	DbgPrint(("驱动程序卸载成功! \n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	char *SSDT[464] = { "NtAccessCheck", "NtWorkerFactoryWorkerReady", "NtAcceptConnectPort", "NtMapUserPhysicalPagesScatter", "NtWaitForSingleObject", "NtCallbackReturn", "NtReadFile", "NtDeviceIoControlFile", "NtWriteFile", "NtRemoveIoCompletion", "NtReleaseSemaphore", "NtReplyWaitReceivePort", "NtReplyPort", "NtSetInformationThread", "NtSetEvent", "NtClose", "NtQueryObject", "NtQueryInformationFile", "NtOpenKey", "NtEnumerateValueKey", "NtFindAtom", "NtQueryDefaultLocale", "NtQueryKey", "NtQueryValueKey", "NtAllocateVirtualMemory", "NtQueryInformationProcess", "NtWaitForMultipleObjects32", "NtWriteFileGather", "NtSetInformationProcess", "NtCreateKey", "NtFreeVirtualMemory", "NtImpersonateClientOfPort", "NtReleaseMutant", "NtQueryInformationToken", "NtRequestWaitReplyPort", "NtQueryVirtualMemory", "NtOpenThreadToken", "NtQueryInformationThread", "NtOpenProcess", "NtSetInformationFile", "NtMapViewOfSection", "NtAccessCheckAndAuditAlarm", "NtUnmapViewOfSection", "NtReplyWaitReceivePortEx", "NtTerminateProcess", "NtSetEventBoostPriority", "NtReadFileScatter", "NtOpenThreadTokenEx", "NtOpenProcessTokenEx", "NtQueryPerformanceCounter", "NtEnumerateKey", "NtOpenFile", "NtDelayExecution", "NtQueryDirectoryFile", "NtQuerySystemInformation", "NtOpenSection", "NtQueryTimer", "NtFsControlFile", "NtWriteVirtualMemory", "NtCloseObjectAuditAlarm", "NtDuplicateObject", "NtQueryAttributesFile", "NtClearEvent", "NtReadVirtualMemory", "NtOpenEvent", "NtAdjustPrivilegesToken", "NtDuplicateToken", "NtContinue", "NtQueryDefaultUILanguage", "NtQueueApcThread", "NtYieldExecution", "NtAddAtom", "NtCreateEvent", "NtQueryVolumeInformationFile", "NtCreateSection", "NtFlushBuffersFile", "NtApphelpCacheControl", "NtCreateProcessEx", "NtCreateThread", "NtIsProcessInJob", "NtProtectVirtualMemory", "NtQuerySection", "NtResumeThread", "NtTerminateThread", "NtReadRequestData", "NtCreateFile", "NtQueryEvent", "NtWriteRequestData", "NtOpenDirectoryObject", "NtAccessCheckByTypeAndAuditAlarm", "NtQuerySystemTime", "NtWaitForMultipleObjects", "NtSetInformationObject", "NtCancelIoFile", "NtTraceEvent", "NtPowerInformation", "NtSetValueKey", "NtCancelTimer", "NtSetTimer", "NtAccessCheckByType", "NtAccessCheckByTypeResultList", "NtAccessCheckByTypeResultListAndAuditAlarm", "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", "NtAcquireProcessActivityReference", "NtAddAtomEx", "NtAddBootEntry", "NtAddDriverEntry", "NtAdjustGroupsToken", "NtAdjustTokenClaimsAndDeviceGroups", "NtAlertResumeThread", "NtAlertThread", "NtAlertThreadByThreadId", "NtAllocateLocallyUniqueId", "NtAllocateReserveObject", "NtAllocateUserPhysicalPages", "NtAllocateUuids", "NtAllocateVirtualMemoryEx", "NtAlpcAcceptConnectPort", "NtAlpcCancelMessage", "NtAlpcConnectPort", "NtAlpcConnectPortEx", "NtAlpcCreatePort", "NtAlpcCreatePortSection", "NtAlpcCreateResourceReserve", "NtAlpcCreateSectionView", "NtAlpcCreateSecurityContext", "NtAlpcDeletePortSection", "NtAlpcDeleteResourceReserve", "NtAlpcDeleteSectionView", "NtAlpcDeleteSecurityContext", "NtAlpcDisconnectPort", "NtAlpcImpersonateClientContainerOfPort", "NtAlpcImpersonateClientOfPort", "NtAlpcOpenSenderProcess", "NtAlpcOpenSenderThread", "NtAlpcQueryInformation", "NtAlpcQueryInformationMessage", "NtAlpcRevokeSecurityContext", "NtAlpcSendWaitReceivePort", "NtAlpcSetInformation", "NtAreMappedFilesTheSame", "NtAssignProcessToJobObject", "NtAssociateWaitCompletionPacket", "NtCallEnclave", "NtCancelIoFileEx", "NtCancelSynchronousIoFile", "NtCancelTimer2", "NtCancelWaitCompletionPacket", "NtCommitComplete", "NtCommitEnlistment", "NtCommitRegistryTransaction", "NtCommitTransaction", "NtCompactKeys", "NtCompareObjects", "NtCompareSigningLevels", "NtCompareTokens", "ArbPreprocessEntry", "NtCompressKey", "NtConnectPort", "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter", "ArbAddReserved", "NtCreateDebugObject", "NtCreateDirectoryObject", "NtCreateDirectoryObjectEx", "NtCreateEnclave", "NtCreateEnlistment", "NtCreateEventPair", "NtCreateIRTimer", "NtCreateIoCompletion", "NtCreateJobObject", "ArbAddReserved", "NtCreateKeyTransacted", "NtCreateKeyedEvent", "NtCreateLowBoxToken", "NtCreateMailslotFile", "NtCreateMutant", "NtCreateNamedPipeFile", "NtCreatePagingFile", "NtCreatePartition", "NtCreatePort", "NtCreatePrivateNamespace", "NtCreateProcess", "NtCreateProfile", "NtCreateProfileEx", "NtCreateRegistryTransaction", "NtCreateResourceManager", "NtCreateSectionEx", "NtCreateSemaphore", "NtCreateSymbolicLinkObject", "NtCreateThreadEx", "NtCreateTimer", "NtCreateTimer2", "NtCreateToken", "NtCreateTokenEx", "NtCreateTransaction", "NtCreateTransactionManager", "NtCreateUserProcess", "NtCreateWaitCompletionPacket", "NtCreateWaitablePort", "NtCreateWnfStateName", "NtCreateWorkerFactory", "NtDebugActiveProcess", "NtDebugContinue", "NtDeleteAtom", "NtDeleteBootEntry", "NtDeleteDriverEntry", "NtDeleteFile", "NtDeleteKey", "NtDeleteObjectAuditAlarm", "NtDeletePrivateNamespace", "NtDeleteValueKey", "NtDeleteWnfStateData", "NtDeleteWnfStateName", "NtDisableLastKnownGood", "NtDisplayString", "NtDrawText", "NtEnableLastKnownGood", "NtEnumerateBootEntries", "NtEnumerateDriverEntries", "NtEnumerateSystemEnvironmentValuesEx", "NtEnumerateTransactionObject", "NtExtendSection", "NtFilterBootOption", "NtFilterToken", "NtFilterTokenEx", "NtFlushBuffersFileEx", "NtFlushInstallUILanguage", "ArbPreprocessEntry", "NtFlushKey", "NtFlushProcessWriteBuffers", "NtFlushVirtualMemory", "NtFlushWriteBuffer", "NtFreeUserPhysicalPages", "NtFreezeRegistry", "NtFreezeTransactions", "NtGetCachedSigningLevel", "NtGetCompleteWnfStateSubscription", "NtGetContextThread", "NtGetCurrentProcessorNumber", "NtGetCurrentProcessorNumberEx", "NtGetDevicePowerState", "NtGetMUIRegistryInfo", "NtGetNextProcess", "NtGetNextThread", "NtGetNlsSectionPtr", "NtGetNotificationResourceManager", "NtGetWriteWatch", "NtImpersonateAnonymousToken", "NtImpersonateThread", "NtInitializeEnclave", "NtInitializeNlsFiles", "NtInitializeRegistry", "NtInitiatePowerAction", "NtIsSystemResumeAutomatic", "NtIsUILanguageComitted", "NtListenPort", "NtLoadDriver", "NtLoadEnclaveData", "NtLoadKey", "NtLoadKey2", "NtLoadKeyEx", "NtLockFile", "NtLockProductActivationKeys", "NtLockRegistryKey", "NtLockVirtualMemory", "NtMakePermanentObject", "NtMakeTemporaryObject", "NtManageHotPatch", "NtManagePartition", "NtMapCMFModule", "NtMapUserPhysicalPages", "NtMapViewOfSectionEx", "NtModifyBootEntry", "NtModifyDriverEntry", "NtNotifyChangeDirectoryFile", "NtNotifyChangeDirectoryFileEx", "NtNotifyChangeKey", "NtNotifyChangeMultipleKeys", "NtNotifyChangeSession", "NtOpenEnlistment", "NtOpenEventPair", "NtOpenIoCompletion", "NtOpenJobObject", "NtOpenKeyEx", "NtOpenKeyTransacted", "NtOpenKeyTransactedEx", "NtOpenKeyedEvent", "NtOpenMutant", "NtOpenObjectAuditAlarm", "NtOpenPartition", "NtOpenPrivateNamespace", "NtOpenProcessToken", "NtOpenRegistryTransaction", "NtOpenResourceManager", "NtOpenSemaphore", "NtOpenSession", "NtOpenSymbolicLinkObject", "NtOpenThread", "NtOpenTimer", "NtOpenTransaction", "NtOpenTransactionManager", "NtPlugPlayControl", "NtPrePrepareComplete", "NtPrePrepareEnlistment", "NtPrepareComplete", "NtPrepareEnlistment", "NtPrivilegeCheck", "NtPrivilegeObjectAuditAlarm", "NtPrivilegedServiceAuditAlarm", "NtPropagationComplete", "NtPropagationFailed", "NtPulseEvent", "NtQueryAuxiliaryCounterFrequency", "NtQueryBootEntryOrder", "NtQueryBootOptions", "NtQueryDebugFilterState", "NtQueryDirectoryFileEx", "NtQueryDirectoryObject", "NtQueryDriverEntryOrder", "NtQueryEaFile", "NtQueryFullAttributesFile", "NtQueryInformationAtom", "NtQueryInformationByName", "NtQueryInformationEnlistment", "NtQueryInformationJobObject", "NtQueryInformationPort", "NtQueryInformationResourceManager", "NtQueryInformationTransaction", "NtQueryInformationTransactionManager", "NtQueryInformationWorkerFactory", "NtQueryInstallUILanguage", "NtQueryIntervalProfile", "NtQueryIoCompletion", "NtQueryLicenseValue", "NtQueryMultipleValueKey", "NtQueryMutant", "NtQueryOpenSubKeys", "NtQueryOpenSubKeysEx", "CmpCleanUpHigherLayerKcbCachesPreCallback", "NtQueryQuotaInformationFile", "NtQuerySecurityAttributesToken", "NtQuerySecurityObject", "NtQuerySecurityPolicy", "NtQuerySemaphore", "NtQuerySymbolicLinkObject", "NtQuerySystemEnvironmentValue", "NtQuerySystemEnvironmentValueEx", "NtQuerySystemInformationEx", "NtQueryTimerResolution", "NtQueryWnfStateData", "NtQueryWnfStateNameInformation", "NtQueueApcThreadEx", "NtRaiseException", "NtRaiseHardError", "NtReadOnlyEnlistment", "NtRecoverEnlistment", "NtRecoverResourceManager", "NtRecoverTransactionManager", "NtRegisterProtocolAddressInformation", "NtRegisterThreadTerminatePort", "NtReleaseKeyedEvent", "NtReleaseWorkerFactoryWorker", "NtRemoveIoCompletionEx", "NtRemoveProcessDebug", "NtRenameKey", "NtRenameTransactionManager", "NtReplaceKey", "NtReplacePartitionUnit", "NtReplyWaitReplyPort", "NtRequestPort", "NtResetEvent", "NtResetWriteWatch", "NtRestoreKey", "NtResumeProcess", "NtRevertContainerImpersonation", "NtRollbackComplete", "NtRollbackEnlistment", "NtRollbackRegistryTransaction", "NtRollbackTransaction", "NtRollforwardTransactionManager", "NtSaveKey", "NtSaveKeyEx", "NtSaveMergedKeys", "NtSecureConnectPort", "NtSerializeBoot", "NtSetBootEntryOrder", "NtSetBootOptions", "NtSetCachedSigningLevel", "NtSetCachedSigningLevel2", "NtSetContextThread", "NtSetDebugFilterState", "NtSetDefaultHardErrorPort", "NtSetDefaultLocale", "NtSetDefaultUILanguage", "NtSetDriverEntryOrder", "NtSetEaFile", "NtSetHighEventPair", "NtSetHighWaitLowEventPair", "NtSetIRTimer", "NtSetInformationDebugObject", "NtSetInformationEnlistment", "NtSetInformationJobObject", "NtSetInformationKey", "NtSetInformationResourceManager", "NtSetInformationSymbolicLink", "NtSetInformationToken", "NtSetInformationTransaction", "NtSetInformationTransactionManager", "NtSetInformationVirtualMemory", "NtSetInformationWorkerFactory", "NtSetIntervalProfile", "NtSetIoCompletion", "NtSetIoCompletionEx", "BvgaSetVirtualFrameBuffer", "NtSetLowEventPair", "NtSetLowWaitHighEventPair", "NtSetQuotaInformationFile", "NtSetSecurityObject", "NtSetSystemEnvironmentValue", "NtSetSystemEnvironmentValueEx", "NtSetSystemInformation", "NtSetSystemPowerState", "NtSetSystemTime", "NtSetThreadExecutionState", "NtSetTimer2", "NtSetTimerEx", "NtSetTimerResolution", "NtSetUuidSeed", "NtSetVolumeInformationFile", "NtSetWnfProcessNotificationEvent", "NtShutdownSystem", "NtShutdownWorkerFactory", "NtSignalAndWaitForSingleObject", "NtSinglePhaseReject", "NtStartProfile", "NtStopProfile", "NtSubscribeWnfStateChange", "NtSuspendProcess", "NtSuspendThread", "NtSystemDebugControl", "NtTerminateEnclave", "NtTerminateJobObject", "NtTestAlert", "NtThawRegistry", "NtThawTransactions", "NtTraceControl", "NtTranslateFilePath", "NtUmsThreadYield", "NtUnloadDriver", "NtUnloadKey", "NtUnloadKey2", "NtUnloadKeyEx", "NtUnlockFile", "NtUnlockVirtualMemory", "NtUnmapViewOfSectionEx", "NtUnsubscribeWnfStateChange", "NtUpdateWnfStateData", "NtVdmControl", "NtWaitForAlertByThreadId", "NtWaitForDebugEvent", "NtWaitForKeyedEvent", "NtWaitForWorkViaWorkerFactory", "NtWaitHighEventPair", "NtWaitLowEventPair" };

	for (size_t i = 0; i < 464; i++)
	{
		// 获取起源地址
		ANSI_STRING ansi = { 0 };
		UNICODE_STRING uncode = { 0 };

		ULONGLONG ssdt_address = GetKeServiceDescriptorTable();
		// DbgPrint("SSDT基地址 = %p \n", ssdt_address);

		// 根据序号得到函数地址
		ULONGLONG address = GetSSDTFunctionAddress(i);
		ULONG offset = GetOffsetAddress(address);

		RtlInitAnsiString(&ansi, SSDT[i]);
		RtlAnsiStringToUnicodeString(&uncode, &ansi, TRUE);
		PULONGLONG source_address = MmGetSystemRoutineAddress(&uncode);
		DbgPrint("序号 => [%d] | 当前地址 => %p | 起源地址 => %p | 相对地址 => %p | SSDT => %s \n", i, address, source_address, offset, SSDT[i]);
	}

	DriverObject->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}

```
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22837360/1699199557954-ac78787f-e1eb-4277-abf9-4d3488a179c0.png#averageHue=%23d1d1d1&clientId=uc1b594ef-97e0-4&from=paste&height=229&id=ube497b9d&originHeight=229&originWidth=598&originalType=binary&ratio=1&rotation=0&showTitle=false&size=129355&status=done&style=none&taskId=u2d14bffb-aef0-4903-a4bf-968c41c944b&title=&width=598)
