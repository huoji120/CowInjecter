#include "head.h"
#include "main.h"
struct moudle_info
{
	uintptr_t bsae;
	uintptr_t size;
};
bool get_moudle_base(PEPROCESS process, moudle_info* kernel32, moudle_info* ntdll, moudle_info* kernelbase) {
	PPEB peb = PsGetProcessPeb(process);
	bool result = false;
	if (peb == NULL)
		return result;
	DebugPrintA("process peb: %p \n", peb);
	//PEB + 0x18 = PEB.Ldr
	auto peb_ldr = *(PDWORD64)((PUCHAR)peb + 0x18);
	//Pebldr + 0x10 = InLoadOrderModuleList
	PLIST_ENTRY module_list_head = (PLIST_ENTRY)((PUCHAR)peb_ldr + 0x10);
	PLIST_ENTRY moudle = module_list_head->Flink;
	/*
		win7: kernel32.dll
		win10: KERNEL32.DLL
	*/
	wchar_t moudle_list[][15] = {
		{L"kernel32.dll"},
		{L"ntdll.dll"},
		{L"kernelbase.dll"},
	};
	while (module_list_head != moudle)
	{
		PLDR_DATA_TABLE_ENTRY info = (PLDR_DATA_TABLE_ENTRY)moudle;
		UNICODE_STRING	str_moudle_name;
		for (size_t i = 0; i < sizeof(moudle_list); i++)
		{
			RtlInitUnicodeString(&str_moudle_name, moudle_list[i]);
			if (BlackBoneSafeSearchString(&info->BaseDllName, &str_moudle_name, true) != -1)
			{
				DebugPrintA("MoudleBase %p Size %p Name %wZ\n", info->DllBase, info->SizeOfImages, info->BaseDllName);
				if (i == 0) {
					kernel32->bsae = (uintptr_t)info->DllBase;
					kernel32->size = (uintptr_t)info->SizeOfImages;
				}
				if (i == 1) {
					ntdll->bsae = (uintptr_t)info->DllBase;
					ntdll->size = (uintptr_t)info->SizeOfImages;
				}
				if (i == 2) {
					kernelbase->bsae = (uintptr_t)info->DllBase;
					kernelbase->size = (uintptr_t)info->SizeOfImages;
				}
				break;
			}
		}
		if (kernel32->bsae && ntdll->bsae && kernelbase->bsae)
			break;
		moudle = moudle->Flink;
	}
	result = kernel32->bsae != NULL && ntdll->bsae != NULL  && kernelbase->bsae != NULL;
	DebugPrintA("kernel32->bsae %p sizeof:%p ntdll->bsae %p kernelbase->bsae %p result: %d \n", kernel32->bsae, kernel32->size, ntdll->bsae, kernelbase->bsae, result);

	return result;
}
uintptr_t get_free_speace(uintptr_t base, size_t size, size_t need_size) {
	size_t return_length;
	
	for (uintptr_t address = (uintptr_t)base; address <= (uintptr_t)base + size; address += sizeof(uintptr_t)) {
		__try
		{
			ProbeForRead((void*)address, need_size, 0x1);
			if (*(uintptr_t*)address == 0x00 || *(uintptr_t*)address == 0x90)
			{
				MEMORY_BASIC_INFORMATION memory_information = { 0 };
				NTSTATUS status = ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)address, (MEMORY_INFORMATION_CLASS)0, &memory_information, need_size, &return_length);
				if (NT_SUCCESS(status)) {
					if ((memory_information.Protect == PAGE_EXECUTE || memory_information.Protect == PAGE_EXECUTE_READ || memory_information.Protect == PAGE_EXECUTE_READWRITE || memory_information.Protect == PAGE_EXECUTE_WRITECOPY) == false) {
						continue;
					}
				}
				DebugPrintA("address : %p \n", address);
				uintptr_t count = 0;
				bool is_good = true;
				uintptr_t max_count = 0;
				for (; count < need_size && is_good; count += sizeof(uintptr_t))
				{
					max_count++;
					auto check_ptr = (uintptr_t*)((PUCHAR)address + count);
					if (*check_ptr != 0x0 && *check_ptr != 0x90)
					{
						is_good = false;
						break;
					}
				}
				if (is_good) {
					DebugPrintA("location Cow virtual address : %p \n", address);
					return address;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			continue;
		}
	}
	return NULL;
}


VOID DriverUnload(PDRIVER_OBJECT driver)
{
	DebugPrintA("[DebugMessage] Unload Driver");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
	DebugPrintA("init Driver \n");
	/*
		³õÊ¼»¯shellcode
	*/
	//uintptr_t size_of_shellcode = CALCSIZE(HkCreateFileW, ShellCodeEnd);
	uintptr_t size_of_shellcode = sizeof(HookCode);
	DebugPrintA("shell code size: %p \n", size_of_shellcode);
	/*
		get a x64 process
	*/
	for (uintptr_t i = 8; i < 100000000; i = i + 4)
	{
		PEPROCESS _eprocess = NULL;
		NTSTATUS nt_status = PsLookupProcessByProcessId((HANDLE)i, &_eprocess);
		if (NT_SUCCESS(nt_status) && _eprocess != NULL)
		{
			ObDereferenceObject(_eprocess);
			bool is_x64_process = PsGetProcessWow64Process(_eprocess) == NULL;
			if (is_x64_process) {
				KAPC_STATE apc;
				KeStackAttachProcess(_eprocess, &apc);
				moudle_info kernel32 = {0};
				moudle_info ntdll = { 0 };
				moudle_info kernelbase = { 0 };
				/*
					is x64 process, get kernel32.dll and kernelbase.dll and ntdll.dll base
				*/
				if (get_moudle_base(_eprocess, &kernel32, &ntdll, &kernelbase)) {
					uintptr_t kernel32_loadlibrary = GetProcAddressR(kernel32.bsae, "LoadLibraryW", TRUE);
					uintptr_t ntdll_wcsstr = GetProcAddressR(ntdll.bsae, "wcsstr", TRUE);
					uintptr_t kernelbase_GetModuleFileNameW = GetProcAddressR(kernelbase.bsae, "GetModuleFileNameW", TRUE);
					uintptr_t kernelbase_CreateFileW = GetProcAddressR(kernelbase.bsae, "CreateFileW", TRUE);

					if (kernel32_loadlibrary && ntdll_wcsstr && kernelbase_GetModuleFileNameW && kernelbase_CreateFileW) {
						uintptr_t hook_function = get_free_speace(kernel32.bsae, kernel32.size, size_of_shellcode + sizeof(void*) + sizeof(CreateFileWT));
						if (hook_function) {
							/*
								Copy shellcode to freespeace
							*/
							_memcpy((PVOID)hook_function, (PVOID)HookCode, size_of_shellcode);
							/*
								hook
							*/
							BYTE _mov_rax[] = {
								0x48, 0xB8 // mov rax, [xxx]
							};
							BYTE _jmp_rax[] = {
								0xFF, 0xE0, // jmp rax
							};
							BYTE shell_code_jmp_back[] = {
								0xCC, 0xCC, //mov rax
								0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //void*
								0xCC, 0xCC, //jmp rax
							};
							uintptr_t function_offset = kernelbase_CreateFileW;
							//backup
							_memcpy(shell_code_jmp_back, (void*)function_offset, sizeof(shell_code_jmp_back));
							/*
								hook_function -> origin_code
							*/
							function_offset = hook_function + size_of_shellcode;
							uintptr_t jmp_back = function_offset;
							_memcpy((void*)function_offset, shell_code_jmp_back, sizeof(shell_code_jmp_back));
							function_offset += sizeof(shell_code_jmp_back);
							/*
								origin_code -> jmp CreateFileW
							*/
							uintptr_t jmp_offset = kernelbase_CreateFileW + sizeof(_mov_rax) + sizeof(_jmp_rax) + sizeof(void*);
							_memcpy((void*)function_offset, _mov_rax, sizeof(_mov_rax));
							function_offset += sizeof(_mov_rax);
							_memcpy((void*)function_offset, &jmp_offset, sizeof(void*));
							function_offset += sizeof(void*);
							_memcpy((void*)function_offset, _jmp_rax, sizeof(_jmp_rax));
							/*
								location shellcode function
							*/
							for (int i = 0; i < size_of_shellcode; i++)
							{
								auto write_ptr = (uintptr_t*)((PUCHAR)hook_function + i);
								if (*write_ptr == 0x1234567812345678)
								{
									_memcpy((void*)write_ptr, (void*)&jmp_back, sizeof(uintptr_t));
									DebugPrintA("[jmp_back]Fix KernelBase.CreateFileW %p \n", jmp_back);
								}
								if (*write_ptr == 0x1234567891ABCDEF)
								{
									_memcpy((void*)write_ptr, (void*)&ntdll_wcsstr, sizeof(uintptr_t));
									DebugPrintA("Fix Ntdll.wcsstr %p \n", ntdll_wcsstr);
								}
								if (*write_ptr == 0x1337567891ABCDEF)
								{
									_memcpy((void*)write_ptr, (void*)&kernelbase_GetModuleFileNameW, sizeof(uintptr_t));
									DebugPrintA("Fix KernelBase.GetModuleFileNameW %p \n", kernelbase_GetModuleFileNameW);
								}
								if (*write_ptr == 0x1234567891AB1337)
								{
									_memcpy((void*)write_ptr, (void*)&kernel32_loadlibrary, sizeof(uintptr_t));
									DebugPrintA("Fix kernel32.loadlibrary %p \n", kernel32_loadlibrary);
								}
							}
							/*
								CreateFileW -> hook_function
							*/
							function_offset = kernelbase_CreateFileW;
							_memcpy((void*)function_offset, _mov_rax, sizeof(_mov_rax));
							function_offset += sizeof(_mov_rax);
							_memcpy((void*)function_offset, &hook_function, sizeof(void*));
							function_offset += sizeof(void*);
							_memcpy((void*)function_offset, _jmp_rax, sizeof(_jmp_rax));
							DebugPrintA("success hooked at: %p \n", hook_function);

						} else {
							DebugPrintA("Cannot free space for shellcode \n");
						}
					}
					else {
						DebugPrintA("can not get export function\n");
					}
				}
				KeUnstackDetachProcess(&apc);
				break;
			}
		}
	}
	driver->DriverUnload = DriverUnload;
	return STATUS_UNSUCCESSFUL;
}
