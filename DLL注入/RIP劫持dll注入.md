通过KeStackAttachProcess函数附加到目标进程<br />通过得到目标进程 Ntdll.dll模块中 LdrLoadDll函数基地址<br />通过ZwGetNextThread函数得到当前线程的句柄<br />通过PsSuspendThread函数暂停当前线程运行<br />通过ZwAllocateVirtualMemory函数将shellcode放到内存，修改RIP指向新的内存地址<br />通过PsResumeThread恢复线程执行我们shellcode<br />通过KeUnstackDetachProcess函数脱离目标进程
```cpp
#include "my_data.h"

typedef struct _INJECT_BUFFER
{
	UCHAR Code[0x200];
	UNICODE_STRING Path;
	UNICODE_STRING32 Path32;
	wchar_t Buffer[488];
	PVOID ModuleHandle;
	ULONG Complete;
	NTSTATUS Status;
	ULONG64 orgRipAddress;
	ULONG64 orgRip;
} INJECT_BUFFER, *PINJECT_BUFFER;

PPsGetThreadTeb g_PsGetThreadTeb = NULL;
PPsResumeThread g_PsResumeThread = NULL;
PPsSuspendThread g_PsSuspendThread = NULL;
PZwGetNextThread g_ZwGetNextThread = NULL;
PPsGetProcessWow64Process g_PsGetProcessWow64Process = NULL;

// 内核特征码定位函数
PVOID SearchOPcode(PDRIVER_OBJECT pObj, PWCHAR DriverName, PCHAR sectionName, PUCHAR opCode, int len, int offset)
{
	PVOID dllBase = NULL;
	UNICODE_STRING uniDriverName;
	PKLDR_DATA_TABLE_ENTRY firstentry;

	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)pObj->DriverSection;

	firstentry = entry;
	RtlInitUnicodeString(&uniDriverName, DriverName);

	// 开始遍历
	while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
		// 如果找到了所需模块则将其基地址返回
		if (entry->FullDllName.Buffer != 0 && entry->BaseDllName.Buffer != 0)
		{
			if (RtlCompareUnicodeString(&uniDriverName, &(entry->BaseDllName), FALSE) == 0)
			{
				dllBase = entry->DllBase;
				break;
			}
		}
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}

	if (dllBase)
	{
		__try
		{
			// 载入模块基地址
			PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)dllBase;
			if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			{
				return NULL;
			}
			// 得到模块NT头
			PIMAGE_NT_HEADERS64 pImageNtHeaders64 = (PIMAGE_NT_HEADERS64)((PUCHAR)dllBase + ImageDosHeader->e_lfanew);

			// 获取节表头
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)pImageNtHeaders64 + sizeof(pImageNtHeaders64->Signature) + sizeof(pImageNtHeaders64->FileHeader) + pImageNtHeaders64->FileHeader.SizeOfOptionalHeader);

			PUCHAR endAddress = 0;
			PUCHAR starAddress = 0;

			// 寻找符合条件的节
			for (int i = 0; i < pImageNtHeaders64->FileHeader.NumberOfSections; i++)
			{
				// 寻找符合条件的表名
				if (memcmp(sectionName, pSectionHeader->Name, strlen(sectionName) + 1) == 0)
				{
					// 取出开始和结束地址
					starAddress = pSectionHeader->VirtualAddress + (PUCHAR)dllBase;
					endAddress = pSectionHeader->VirtualAddress + (PUCHAR)dllBase + pSectionHeader->SizeOfRawData;
					break;
				}
				// 遍历下一个节
				pSectionHeader++;
			}
			if (endAddress && starAddress)
			{
				// 找到会开始寻找特征
				for (; starAddress < endAddress - len - 1; starAddress++)
				{
					// 验证访问权限
					if (MmIsAddressValid(starAddress))
					{
						int i = 0;
						for (; i < len; i++)
						{
							// 判断是否为通配符'*'
							if (opCode[i] == 0x2a)
								continue;

							// 找到了一个字节则跳出
							if (opCode[i] != starAddress[i])
								break;
						}
						// 找到次数完全匹配则返回地址
						if (i == len)
						{
							return starAddress + offset;
						}
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
	}

	return NULL;
}

// 生成64位注入代码
PINJECT_BUFFER GetNativeCode(PVOID LdrLoadDll, PUNICODE_STRING DllFullPath, ULONGLONG orgEip)
{
	SIZE_T Size = PAGE_SIZE;
	PINJECT_BUFFER InjectBuffer = NULL;
	UCHAR Code[] = {
		0x41, 0x57,                             // push r15
		0x41, 0x56,                             // push r14
		0x41, 0x55,                             // push r13
		0x41, 0x54,                             // push r12
		0x41, 0x53,                             // push r11
		0x41, 0x52,                             // push r10
		0x41, 0x51,                             // push r9
		0x41, 0x50,                             // push r8
		0x50,                                   // push rax
		0x51,                                   // push rcx
		0x53,                                   // push rbx
		0x52,                                   // push rdx
		0x55,                                   // push rbp
		0x54,                                   // push rsp
		0x56,                                   // push rsi
		0x57,                                   // push rdi
		0x66, 0x9C,                             // pushf
		0x48, 0x83, 0xEC, 0x26,                 // sub rsp, 0x28
		0x48, 0x31, 0xC9,                       // xor rcx, rcx
		0x48, 0x31, 0xD2,                       // xor rdx, rdx
		0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +38
		0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +48
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +58
		0xFF, 0xD0,                             // call rax
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +70
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [rdx], CALL_COMPLETE 
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   offset +86
		0x89, 0x02,                             // mov [rdx], eax
		0x48, 0x83, 0xC4, 0x26,                 // add rsp, 0x28
		0x66, 0x9D,                             // popf
		0x5F,                                   // pop rdi
		0x5E,                                   // pop rsi 
		0x5C,                                   // pop rsp
		0x5D,                                   // pop rbp
		0x5A,                                   // pop rdx
		0x5B,                                   // pop rbx
		0x59,                                   // pop rcx
		0x58,                                   // pop rax
		0x41, 0x58,                             // pop r8
		0x41, 0x59,                             // pop r9
		0x41, 0x5A,                             // pop r10
		0x41, 0x5B,                             // pop r11
		0x41, 0x5C,                             // pop r12
		0x41, 0x5D,                             // pop r13
		0x41, 0x5E,                             // pop r14
		0x41, 0x5F,                             // pop r15
		0x50,                                   // push rax
		0x50,                                   // push rax 
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, orgEip offset +130
		0x48, 0x89, 0x44, 0x24, 0x08,           // mov [rsp+8],rax
		0x58,                                   // pop rax
		0xC3                                    // ret
	};

	// 在当前进程内分配内存空间
	if (NT_SUCCESS(ZwAllocateVirtualMemory(ZwCurrentProcess(), &InjectBuffer, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		// 初始化路径变量与长度参数
		PUNICODE_STRING UserPath = &InjectBuffer->Path;
		UserPath->Length = DllFullPath->Length;
		UserPath->MaximumLength = DllFullPath->MaximumLength;
		UserPath->Buffer = InjectBuffer->Buffer;

		RtlUnicodeStringCopy(UserPath, DllFullPath);

		// 将ShellCode拷贝到InjectBuffer中等待处理
		memcpy(InjectBuffer, Code, sizeof(Code));

		// 修改代码模板，将指定位置替换为我们自己的代码
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 38) = (ULONGLONG)UserPath;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 48) = (ULONGLONG)& InjectBuffer->ModuleHandle;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 58) = (ULONGLONG)LdrLoadDll;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 70) = (ULONGLONG)& InjectBuffer->Complete;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 86) = (ULONGLONG)& InjectBuffer->Status;
		*(ULONGLONG*)((PUCHAR)InjectBuffer + 130) = orgEip;

		return InjectBuffer;
	}
	return NULL;
}

// 生成32位注入代码
PINJECT_BUFFER GetWow64Code(PVOID LdrLoadDll, PUNICODE_STRING DllFullPath, ULONG orgEip)
{
	SIZE_T Size = PAGE_SIZE;
	PINJECT_BUFFER InjectBuffer = NULL;

	UCHAR Code[] = {
		0x60,                                   // pushad
		0x9c,                                   // pushfd
		0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +3 
		0x68, 0, 0, 0, 0,                       // push ModuleFileName          offset +8
		0x6A, 0,                                // push Flags  
		0x6A, 0,                                // push PathToFile
		0xE8, 0, 0, 0, 0,                       // call LdrLoadDll              offset +17
		0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +22
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [edx], CALL_COMPLETE     
		0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +33
		0x89, 0x02,                             // mov [edx], eax
		0x9d,                                   // popfd
		0x61,                                   // popad
		0x50,                                   // push eax
		0x50,                                   // push eax
		0xb8, 0, 0, 0, 0,                       // mov eax, orgEip
		0x89, 0x44, 0x24, 0x04,                 // mov [esp+4],eax
		0x58,                                   // pop eax
		0xc3                                    // ret
	};

	/*
	如下代码中通过定义Code并写入调用模块加载的汇编指令集，通过运用ZwAllocateVirtualMemory在当前进程也就是附加到对端以后的进程内动态开辟了一块长度为Size的内存空间并赋予了PAGE_EXECUTE_READWRITE读写执行属性，
	由于Code代码无法直接使用，则此处调用RtlCopyMemory将指令拷贝到了InjectBuffer其目的是用于后续的填充工作，最后通过*(ULONG*)((PUCHAR)InjectBuffer + 3)的方式将需要使用的函数地址，
	模块信息等依次填充到汇编代码的指定位置，并返回InjectBuffer指针。
	*/

	// 在当前进程内分配内存空间
	if (NT_SUCCESS(ZwAllocateVirtualMemory(ZwCurrentProcess(), &InjectBuffer, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		// 初始化路径变量与长度参数
		PUNICODE_STRING32 pUserPath = &InjectBuffer->Path32;
		pUserPath->Length = DllFullPath->Length;
		pUserPath->MaximumLength = DllFullPath->MaximumLength;
		pUserPath->Buffer = (ULONG)(ULONG_PTR)InjectBuffer->Buffer;

		// 将ShellCode拷贝到InjectBuffer中等待处理
		memcpy((PVOID)pUserPath->Buffer, DllFullPath->Buffer, DllFullPath->Length);
		memcpy(InjectBuffer, Code, sizeof(Code));

		// 修改代码模板，将指定位置替换为我们自己的代码
		*(ULONG*)((PUCHAR)InjectBuffer + 3) = (ULONG)(ULONG_PTR)& InjectBuffer->ModuleHandle;
		*(ULONG*)((PUCHAR)InjectBuffer + 8) = (ULONG)(ULONG_PTR)pUserPath;
		*(ULONG*)((PUCHAR)InjectBuffer + 17) = (ULONG)((ULONG_PTR)LdrLoadDll - ((ULONG_PTR)InjectBuffer + 17) - 5 + 1);
		*(ULONG*)((PUCHAR)InjectBuffer + 22) = (ULONG)(ULONG_PTR)& InjectBuffer->Complete;
		*(ULONG*)((PUCHAR)InjectBuffer + 33) = (ULONG)(ULONG_PTR)& InjectBuffer->Status;
		*(ULONG*)((PUCHAR)InjectBuffer + 44) = orgEip;
		return InjectBuffer;
	}

	return NULL;
}

// 设置线程执行地址
NTSTATUS SetThreadStartAddress(PETHREAD pEthread, BOOLEAN isWow64, PVOID LdrLoadDll, PUNICODE_STRING DllFullPath, PINJECT_BUFFER *allcateAddress)
{
	__try
	{
		// 判断是32位则执行
		if (isWow64)
		{
			// 得到线程TEB
			PVOID pTeb = g_PsGetThreadTeb(pEthread);
			if (pTeb)
			{
				// 得到当前线程上下文
				PWOW64_CONTEXT  pCurrentContext = (PWOW64_CONTEXT)(*(ULONG64*)((ULONG64)pTeb + WOW64CONTEXTOFFSET));
				ProbeForRead((PVOID)pCurrentContext, sizeof(pCurrentContext), sizeof(CHAR));

				// 生成注入代码
				PINJECT_BUFFER newAddress = GetWow64Code(LdrLoadDll, DllFullPath, pCurrentContext->Eip);
				if (newAddress)
				{
					// 替换上下文地址到内存中
					newAddress->orgRipAddress = (ULONG64)& (pCurrentContext->Eip);
					newAddress->orgRip = pCurrentContext->Eip;
					*allcateAddress = newAddress;
					pCurrentContext->Eip = (ULONG)(ULONG64)(newAddress);
				}
				return STATUS_SUCCESS;
			}
		}
		// 执行64位代码
		else
		{	
			if (MmIsAddressValid((PVOID)* (ULONG64*)((ULONG64)pEthread + INITIALSTACKOFFSET)))
			{	// InitialStack
				PKTRAP_FRAME pCurrentTrap = (PKTRAP_FRAME)(*(ULONG64*)((ULONG64)pEthread + INITIALSTACKOFFSET) - sizeof(KTRAP_FRAME));
				PINJECT_BUFFER newAddress = GetNativeCode(LdrLoadDll, DllFullPath, pCurrentTrap->Rip);
				if (newAddress)
				{
					// 替换当前RIP地址
					newAddress->orgRipAddress = (ULONG64)& (pCurrentTrap->Rip);
					newAddress->orgRip = pCurrentTrap->Rip;
					*allcateAddress = newAddress;
					pCurrentTrap->Rip = (ULONG64)newAddress;
				}
			}
			return STATUS_SUCCESS;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	return STATUS_UNSUCCESSFUL;
}

// 得到当前用户进程下的模块基址
PVOID GetUserModule(IN PEPROCESS EProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN IsWow64)
{
	if (EProcess == NULL)
		return NULL;
	__try
	{
		// 执行32位
		if (IsWow64)
		{
			// 获取32位下的PEB进程环境块
			PPEB32 Peb32 = (PPEB32)g_PsGetProcessWow64Process(EProcess);
			if (Peb32 == NULL)
				return NULL;

			if (!Peb32->Ldr)
				return NULL;

			// 循环遍历链表 寻找模块
			for (PLIST_ENTRY32 ListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList.Flink;
				ListEntry != &((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList;
				ListEntry = (PLIST_ENTRY32)ListEntry->Flink)
			{
				UNICODE_STRING UnicodeString;
				PLDR_DATA_TABLE_ENTRY32 LdrDataTableEntry32 = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

				RtlUnicodeStringInit(&UnicodeString, (PWCH)LdrDataTableEntry32->BaseDllName.Buffer);
				if (RtlCompareUnicodeString(&UnicodeString, ModuleName, TRUE) == 0)
					return (PVOID)LdrDataTableEntry32->DllBase;
			}
		}
		// 执行64位
		else
		{
			// 得到64位PEB进程环境块
			PPEB Peb = PsGetProcessPeb(EProcess);
			if (!Peb)
				return NULL;

			if (!Peb->Ldr)
				return NULL;

			for (PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink;
				ListEntry != &Peb->Ldr->InLoadOrderModuleList;
				ListEntry = ListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (RtlCompareUnicodeString(&LdrDataTableEntry->BaseDllName, ModuleName, TRUE) == 0)
					return LdrDataTableEntry->DllBase;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	return NULL;
}

// 根据函数名得到导出表地址
PVOID GetModuleExport(IN PVOID ModuleBase, IN PCCHAR FunctionName)
{
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	PIMAGE_NT_HEADERS32 ImageNtHeaders32 = NULL;
	PIMAGE_NT_HEADERS64 ImageNtHeaders64 = NULL;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = NULL;
	ULONG ExportDirectorySize = 0;
	ULONG_PTR FunctionAddress = 0;

	if (ModuleBase == NULL)
		return NULL;

	__try
	{
		// 判断是否是DOS头
		if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return NULL;
		}

		// 获取PE结构节NT头
		ImageNtHeaders32 = (PIMAGE_NT_HEADERS32)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);
		ImageNtHeaders64 = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);

		// 判断是否是64位
		if (ImageNtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			// 如果是64位则执行如下
			ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)ModuleBase);
			ExportDirectorySize = ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		}
		else
		{
			// 如果32位则执行如下
			ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)ModuleBase);
			ExportDirectorySize = ImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		}

		// 取出导出表Index，名字，函地址等
		PUSHORT pAddressOfOrds = (PUSHORT)(ImageExportDirectory->AddressOfNameOrdinals + (ULONG_PTR)ModuleBase);
		PULONG  pAddressOfNames = (PULONG)(ImageExportDirectory->AddressOfNames + (ULONG_PTR)ModuleBase);
		PULONG  pAddressOfFuncs = (PULONG)(ImageExportDirectory->AddressOfFunctions + (ULONG_PTR)ModuleBase);

		// 循环导出表
		for (ULONG i = 0; i < ImageExportDirectory->NumberOfFunctions; ++i)
		{
			USHORT OrdIndex = 0xFFFF;
			PCHAR  pName = NULL;

			// 说明是序号导出
			if ((ULONG_PTR)FunctionName <= 0xFFFF)
			{
				// 得到函数序号
				OrdIndex = (USHORT)i;
			}
			// 说明是名字导出
			else if ((ULONG_PTR)FunctionName > 0xFFFF && i < ImageExportDirectory->NumberOfNames)
			{
				// 得到函数名
				pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)ModuleBase);
				OrdIndex = pAddressOfOrds[i];
			}

			else
				return NULL;

			// 判断函数名是否符合
			if (((ULONG_PTR)FunctionName <= 0xFFFF && (USHORT)((ULONG_PTR)FunctionName) == OrdIndex + ImageExportDirectory->Base) ||
				((ULONG_PTR)FunctionName > 0xFFFF && strcmp(pName, FunctionName) == 0))
			{
				// 得到完整地址
				FunctionAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)ModuleBase;
				break;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	return (PVOID)FunctionAddress;
}

// DLL模块注入线程函数
NTSTATUS KernelInjectDLL(ULONG pid, PUNICODE_STRING DllFullPath, PINJECT_BUFFER* allcateAddress)
{
	PEPROCESS pEprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pEprocess)))
	{
		// 附加到进程内
		KAPC_STATE kApc = { 0 };
		KeStackAttachProcess(pEprocess, &kApc);

		// 得到Ntdll.dll模块基址
		UNICODE_STRING ntdllString = RTL_CONSTANT_STRING(L"Ntdll.dll");
		PVOID NtdllAddress = GetUserModule(pEprocess, &ntdllString, g_PsGetProcessWow64Process(pEprocess) != 0);
		if (!NtdllAddress)
		{
			KeUnstackDetachProcess(&kApc);
			ObDereferenceObject(pEprocess);
			return STATUS_UNSUCCESSFUL;
		}

		// 得到LdrLoadDLL模块的基址
		PVOID LdrLoadDll = GetModuleExport(NtdllAddress, "LdrLoadDll");
		if (!LdrLoadDll)
		{
			KeUnstackDetachProcess(&kApc);
			ObDereferenceObject(pEprocess);
			return STATUS_UNSUCCESSFUL;
		}

		// 得到下一个线程对象
		HANDLE threadHandle = NULL;
		// (HANDLE)-1表示当前进程，0x1FFFFF表示所有线程
		if (NT_SUCCESS(g_ZwGetNextThread((HANDLE)-1, (HANDLE)0, 0x1FFFFF, 0x240, 0, &threadHandle)))
		{
			PVOID threadObj = NULL;
			NTSTATUS state = ObReferenceObjectByHandle(threadHandle, 0x1FFFFF, *PsThreadType, KernelMode, &threadObj, NULL);
			if (NT_SUCCESS(state))
			{
				// 暂停线程
				g_PsSuspendThread(threadObj, NULL);

				// 设置线程ShellCode代码
				SetThreadStartAddress(threadObj, g_PsGetProcessWow64Process(pEprocess) != 0, LdrLoadDll, DllFullPath, allcateAddress);

				// 恢复线程
				g_PsResumeThread(threadObj, NULL);
				ObDereferenceObject(threadObj);
			}
			NtClose(threadHandle);
		}

		KeUnstackDetachProcess(&kApc);
		ObDereferenceObject(pEprocess);
	}
	return STATUS_SUCCESS;
}

NTSTATUS UnDriver(PDRIVER_OBJECT driver)
{
	DbgPrint("卸载完成\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
	/*
	kd> uf PsSuspendThread
	nt_fffff80003e0e000!PsSuspendThread:
	fffff800`040cd5e8 4889542410      mov     qword ptr [rsp+10h],rdx
	fffff800`040cd5ed 48894c2408      mov     qword ptr [rsp+8],rcx
	fffff800`040cd5f2 53              push    rbx
	fffff800`040cd5f3 56              push    rsi
	fffff800`040cd5f4 57              push    rdi
	fffff800`040cd5f5 4154            push    r12
	fffff800`040cd5f7 4155            push    r13
	fffff800`040cd5f9 4883ec40        sub     rsp,40h
	fffff800`040cd5fd 4c8bea          mov     r13,rdx
	fffff800`040cd600 488bf1          mov     rsi,rcx		// 特征码从这里开始，减24回到第一条
	fffff800`040cd603 33ff            xor     edi,edi
	fffff800`040cd605 897c2424        mov     dword ptr [rsp+24h],edi
	fffff800`040cd609 654c8b242588010000 mov   r12,qword ptr gs:[188h]
	fffff800`040cd612 4c89a42480000000 mov     qword ptr [rsp+80h],r12
	fffff800`040cd61a 6641ff8c24c4010000 dec   word ptr [r12+1C4h]
	fffff800`040cd623 4881c138040000  add     rcx,438h
	fffff800`040cd62a 0f0d09          prefetchw [rcx]
	fffff800`040cd62d 488b01          mov     rax,qword ptr [rcx]
	fffff800`040cd630 4883e0fe        and     rax,0FFFFFFFFFFFFFFFEh
	fffff800`040cd634 488d5002        lea     rdx,[rax+2]
	fffff800`040cd638 f0480fb111      lock cmpxchg qword ptr [rcx],rdx
	fffff800`040cd63d 0f85fd370c00    jne     nt_fffff80003e0e000! ?? ::NNGAKEGL::`string'+0x277a0 (fffff800`04190e40)  Branch
	*/
	UCHAR SuspendOpCode[] = { 0x48, 0x8b, 0xf1, 0x33, 0xff, 0x89, 0x7c, 0x24, 0x24, 0x65, 0x4c, 0x8b, 0x24, 0x25, 0x88,0x01 };

	/*
	kd> uf PsResumeThread
	nt_fffff80003e0e000!PsResumeThread:
	fffff800`041d3e00 4053            push    rbx
	fffff800`041d3e02 4883ec20        sub     rsp,20h
	fffff800`041d3e06 488bda          mov     rbx,rdx		// 假设特征码从这里开始，找到后只需要减6就回到第一条
	fffff800`041d3e09 e892f1c8ff      call    nt_fffff80003e0e000!KeResumeThread (fffff800`03e62fa0)
	fffff800`041d3e0e 4885db          test    rbx,rbx
	fffff800`041d3e11 7402            je      nt_fffff80003e0e000!PsResumeThread+0x15 (fffff800`041d3e15)  Branch
	*/
	UCHAR ResumeOpCode[] = { 0x48, 0x8b, 0xda, 0xe8, 0x92, 0xf1, 0xc8, 0xff, 0x48, 0x85, 0xdb, 0x74, 0x02 };

	/*
	kd> uf ZwGetNextThread
	nt_fffff80003e0e000!ZwGetNextThread:
	fffff800`03ea0320 488bc4          mov     rax,rsp
	fffff800`03ea0323 fa              cli
	fffff800`03ea0324 4883ec10        sub     rsp,10h		// 从这里开始
	fffff800`03ea0328 50              push    rax
	fffff800`03ea0329 9c              pushfq
	fffff800`03ea032a 6a10            push    10h
	fffff800`03ea032c 488d057d500000  lea     rax,[nt_fffff80003e0e000!KiServiceLinkage (fffff800`03ea53b0)]
	fffff800`03ea0333 50              push    rax
	fffff800`03ea0334 b8cf000000      mov     eax,0CFh
	fffff800`03ea0339 e9c2f30000      jmp     nt_fffff80003e0e000!KiServiceInternal (fffff800`03eaf700)  Branch
	*/
	UCHAR GetNextThreadOpCode[] = { 0x48, 0x83, 0xec, 0x10, 0x50, 0x9c, 0x6a, 0x10, 0x48, 0x8d, 0x05, 0x7d, 0x50 };

	// 特征码检索PsSuspendThread函数基址
	g_PsSuspendThread = (PPsSuspendThread)SearchOPcode(Driver, L"ntoskrnl.exe", "PAGE", SuspendOpCode, sizeof(SuspendOpCode), -0x18);
	DbgPrint("PsSuspendThread = %p \n", g_PsSuspendThread);

	// 特征码检索PsResumeThread基址
	g_PsResumeThread = (PPsResumeThread)SearchOPcode(Driver, L"ntoskrnl.exe", "PAGE", ResumeOpCode, sizeof(ResumeOpCode), -0x6);
	DbgPrint("PsResumeThread = %p \n", g_PsResumeThread);

	// 特征码检索ZwGetNextThread基址
	g_PsResumeThread = (PZwGetNextThread)SearchOPcode(Driver, L"ntoskrnl.exe", "PAGE", GetNextThreadOpCode, sizeof(GetNextThreadOpCode), -0x4);
	DbgPrint("ZwGetNextThread = %p \n", g_ZwGetNextThread);

	// 动态获取内存中的PsGetThreadTeb基址
	UNICODE_STRING PsGetThreadTebString = RTL_CONSTANT_STRING(L"PsGetThreadTeb");
	g_PsGetThreadTeb = (PPsGetThreadTeb)MmGetSystemRoutineAddress(&PsGetThreadTebString);
	DbgPrint("PsGetThreadTeb = %p \n", g_PsGetThreadTeb);

	// 动态获取内存中的PsGetProcessWow64Process基址
	UNICODE_STRING PsGetProcessWow64ProcessString = RTL_CONSTANT_STRING(L"PsGetProcessWow64Process");
	g_PsGetProcessWow64Process = (PPsGetProcessWow64Process)MmGetSystemRoutineAddress(&PsGetProcessWow64ProcessString);
	DbgPrint("PsGetProcessWow64Process = %p \n", g_PsGetProcessWow64Process);

	// 注入代码
	ULONG ProcessID = 2552;
	UNICODE_STRING InjectDllPath = RTL_CONSTANT_STRING(L"C:\\Windows\\System32\\demo.dll");
	PINJECT_BUFFER AllcateAddress = NULL;

	// 执行线程注入
	NTSTATUS Status = KernelInjectDLL(ProcessID, &InjectDllPath, &AllcateAddress);
	if (Status == STATUS_SUCCESS)
	{
		DbgPrint("[*] 线程注入PID = %d | DLL = %wZ \n", ProcessID, InjectDllPath);
	}

	Driver->DriverUnload = UnDriver;
	return STATUS_SUCCESS;
}

```
```cpp
#include <ntifs.h>
#include <windef.h>
#include <intrin.h>
#include <ntimage.h>
#include <ntstrsafe.h>

// 线程结构体偏移值
#define MAXCOUNTS 0x200
#define INITIALSTACKOFFSET 0x28
#define WOW64CONTEXTOFFSET 0x1488
#define WOW64_SIZE_OF_80387_REGISTERS 80
#define WOW64_MAXIMUM_SUPPORTED_EXTENSION 512

// 导出函数
NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

// 定义自定义函数指针
typedef PVOID(NTAPI* PPsGetThreadTeb)(IN PETHREAD Thread);
typedef PVOID(NTAPI* PPsGetProcessWow64Process)(_In_ PEPROCESS Process);
typedef NTSTATUS(NTAPI* PPsResumeThread)(PETHREAD Thread, OUT PULONG PreviousCount);
typedef NTSTATUS(NTAPI* PPsSuspendThread)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS(NTAPI* PZwGetNextThread)(_In_ HANDLE ProcessHandle, _In_ HANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Flags, _Out_ PHANDLE NewThreadHandle);

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY
{
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
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, *PPEB32;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, *PPEB;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	ULONG UnKnow;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

typedef struct _WOW64_FLOATING_SAVE_AREA
{
	DWORD ControlWord;
	DWORD StatusWord;
	DWORD TagWord;
	DWORD ErrorOffset;
	DWORD ErrorSelector;
	DWORD DataOffset;
	DWORD DataSelector;
	BYTE RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
	DWORD Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA;

typedef struct _WOW64_CONTEXT
{
	DWORD padding;
	DWORD ContextFlags;
	DWORD Dr0;
	DWORD Dr1;
	DWORD Dr2;
	DWORD Dr3;
	DWORD Dr6;
	DWORD Dr7;
	WOW64_FLOATING_SAVE_AREA FloatSave;
	DWORD SegGs;
	DWORD SegFs;
	DWORD SegEs;
	DWORD SegDs;
	DWORD Edi;
	DWORD Esi;
	DWORD Ebx;
	DWORD Edx;
	DWORD Ecx;
	DWORD Eax;
	DWORD Ebp;
	DWORD Eip;
	DWORD SegCs;
	DWORD EFlags;
	DWORD Esp;
	DWORD SegSs;
	BYTE ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];
} WOW64_CONTEXT, *PWOW64_CONTEXT;



```
