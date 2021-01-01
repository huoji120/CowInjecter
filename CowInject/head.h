#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <WinDef.h>
#include <intrin.h>
#define DebugPrintA(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,__VA_ARGS__)
#define HUOJI_POOL_TAG 'huoJ'
#define CALCSIZE(n,f) (ULONG_PTR)f - (ULONG_PTR)n 
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(unsigned __int64 *)(name)
#define DEREF_32( name )*(unsigned long *)(name)
#define DEREF_16( name )*(unsigned short *)(name)
#define DEREF_8( name )*(UCHAR *)(name)
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(NTAPI* NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);

typedef BOOL(WINAPI* ReadFileT)(HANDLE, LPVOID, DWORD, LPDWORD, PVOID);
typedef DWORD(WINAPI* GetFileSizeT)(HANDLE, LPDWORD);
typedef BOOL(WINAPI* CloseHandleT)(HANDLE);

#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D
#define LOADLIBRARYA_HASH				0xEC0E4E8E
#define GETPROCADDRESS_HASH				0x7C0DFCAA
#define VIRTUALALLOC_HASH				0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH	0x534C0AB8
#define HASH_KEY						13
#define DLL_PROCESS_ATTACH				1    
#define DLL_THREAD_ATTACH				2    
#define DLL_THREAD_DETACH				3    
#define DLL_PROCESS_DETACH				0    

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,                 // 0x00 SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation,             // 0x01 SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation,           // 0x02
	SystemTimeOfDayInformation,             // 0x03
	SystemPathInformation,                  // 0x04
	SystemProcessInformation,               // 0x05
	SystemCallCountInformation,             // 0x06
	SystemDeviceInformation,                // 0x07
	SystemProcessorPerformanceInformation,  // 0x08
	SystemFlagsInformation,                 // 0x09
	SystemCallTimeInformation,              // 0x0A
	SystemModuleInformation,                // 0x0B SYSTEM_MODULE_INFORMATION
	SystemLocksInformation,                 // 0x0C
	SystemStackTraceInformation,            // 0x0D
	SystemPagedPoolInformation,             // 0x0E
	SystemNonPagedPoolInformation,          // 0x0F
	SystemHandleInformation,                // 0x10
	SystemObjectInformation,                // 0x11
	SystemPageFileInformation,              // 0x12
	SystemVdmInstemulInformation,           // 0x13
	SystemVdmBopInformation,                // 0x14
	SystemFileCacheInformation,             // 0x15
	SystemPoolTagInformation,               // 0x16
	SystemInterruptInformation,             // 0x17
	SystemDpcBehaviorInformation,           // 0x18
	SystemFullMemoryInformation,            // 0x19
	SystemLoadGdiDriverInformation,         // 0x1A
	SystemUnloadGdiDriverInformation,       // 0x1B
	SystemTimeAdjustmentInformation,        // 0x1C
	SystemSummaryMemoryInformation,         // 0x1D
	SystemNextEventIdInformation,           // 0x1E
	SystemEventIdsInformation,              // 0x1F
	SystemCrashDumpInformation,             // 0x20
	SystemExceptionInformation,             // 0x21
	SystemCrashDumpStateInformation,        // 0x22
	SystemKernelDebuggerInformation,        // 0x23
	SystemContextSwitchInformation,         // 0x24
	SystemRegistryQuotaInformation,         // 0x25
	SystemExtendServiceTableInformation,    // 0x26
	SystemPrioritySeperation,               // 0x27
	SystemPlugPlayBusInformation,           // 0x28
	SystemDockInformation,                  // 0x29
	//SystemPowerInformation,               // 0x2A
	//SystemProcessorSpeedInformation,      // 0x2B
	//SystemCurrentTimeZoneInformation,     // 0x2C
	//SystemLookasideInformation            // 0x2D

} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImages;
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
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;
typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY
{
	ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX
	SIZE_T Size;
	ULONG_PTR Value;
	ULONG Unknown;
} NT_PROC_THREAD_ATTRIBUTE_ENTRY, * NT_PPROC_THREAD_ATTRIBUTE_ENTRY;
typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST
{
	ULONG Length;
	NT_PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST, * PNT_PROC_THREAD_ATTRIBUTE_LIST;

typedef struct _SECURITY_ATTRIBUTES {
	DWORD nLength;
	LPVOID lpSecurityDescriptor;
	BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, * PSECURITY_ATTRIBUTES, * LPSECURITY_ATTRIBUTES;
typedef HANDLE(WINAPI* CreateFileWT)(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
	);
typedef DWORD(WINAPI* GetModuleFileNameWT)(HMODULE hModule, LPCWSTR lpFilename, DWORD nSize);
typedef wchar_t* (WINAPI* wcsstrAt)(wchar_t const* _String1, wchar_t const* _String);
typedef HMODULE(WINAPI* LoadLibraryWT)(_In_ LPCWSTR lpLibFileName);
#ifdef __cplusplus  
extern "C"
{
#endif  
#include <NTDDK.h>  
    NTSYSAPI
        NTSTATUS
        NTAPI
        ZwQuerySystemInformation(
            IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
            OUT PVOID SystemInformation,
            IN ULONG SystemInformationLength,
            OUT PULONG ReturnLength OPTIONAL
        );
	NTKERNELAPI
		NTSTATUS
		ObReferenceObjectByName(
			IN PUNICODE_STRING ObjectName,
			IN ULONG Attributes,
			IN PACCESS_STATE PassedAccessState,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_TYPE ObjectType,
			IN KPROCESSOR_MODE AccessMode,
			IN OUT PVOID ParseContext,
			OUT PVOID* Object
		);
	extern POBJECT_TYPE* IoDriverObjectType;

	ULONG
		NTAPI
		KeCapturePersistentThreadState(
			IN PCONTEXT Context,
			IN PKTHREAD Thread,
			IN ULONG BugCheckCode,
			IN ULONG BugCheckParameter1,
			IN ULONG BugCheckParameter2,
			IN ULONG BugCheckParameter3,
			IN ULONG BugCheckParameter4,
			OUT PVOID VirtualAddress
		);
	NTSYSAPI
		PVOID
		NTAPI
		RtlImageDirectoryEntryToData(
			PVOID ImageBase,
			BOOLEAN MappedAsImage,
			USHORT DirectoryEntry,
			PULONG Size
		);
	NTKERNELAPI
		PPEB
		NTAPI
		PsGetProcessPeb(IN PEPROCESS Process);
	NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(IN PEPROCESS Process);
	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwProtectVirtualMemory(
			IN HANDLE ProcessHandle,
			IN OUT PVOID* BaseAddress,
			IN OUT SIZE_T* NumberOfBytesToProtect,
			IN ULONG NewAccessProtection,
			OUT PULONG OldAccessProtection
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwQueryInformationThread(
			IN HANDLE ThreadHandle,
			IN THREADINFOCLASS ThreadInformationClass,
			OUT PVOID ThreadInformation,
			IN ULONG ThreadInformationLength,
			OUT PULONG ReturnLength OPTIONAL
		);


#ifdef __cplusplus  
}
#endif