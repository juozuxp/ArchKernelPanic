#pragma once
#ifndef KM_Imports_HEADER_INCLUDED
#define KM_Imports_HEADER_INCLUDED

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <ntdddisk.h>
#include <windef.h>
#include <stdlib.h>
#include <string.h>
#include "PEHeaders.h"
#include "..\both\GeneralStructures.h"
#include "..\both\GeneralErrors.h"

extern "C"
{
	int _fltused = 0;
}

#define RTL_MAX_DRIVE_LETTERS 32
#define MAX_PATH          260

#define SeCreateTokenPrivilege 2
#define SeAssignPrimaryTokenPrivilege 3
#define SeLockMemoryPrivilege 4
#define SeIncreaseQuotaPrivilege 5
#define SeUnsolicitedInputPrivilege 0
#define SeMachineAccountPrivilege 6
#define SeTcbPrivilege 7
#define SeSecurityPrivilege 8
#define SeTakeOwnershipPrivilege 9
#define SeLoadDriverPrivilege 10
#define SeSystemProfilePrivilege 11
#define SeSystemtimePrivilege 12
#define SeProfileSingleProcessPrivilege 13
#define SeIncreaseBasePriorityPrivilege 14
#define SeCreatePagefilePrivilege 15
#define SeCreatePermanentPrivilege 16
#define SeBackupPrivilege 17
#define SeRestorePrivilege 18
#define SeShutdownPrivilege 19
#define SeDebugPrivilege 20
#define SeAuditPrivilege 21
#define SeSystemEnvironmentPrivilege 22
#define SeChangeNotifyPrivilege 23
#define SeRemoteShutdownPrivilege 24
#define SeUndockPrivilege 25
#define SeSyncAgentPrivilege 26
#define SeEnableDelegationPrivilege 27
#define SeManageVolumePrivilege 28
#define SeImpersonatePrivilege 29
#define SeCreateGlobalPrivilege 30
#define SeTrustedCredManAccessPrivilege 31
#define SeRelabelPrivilege 32
#define SeIncreaseWorkingSetPrivilege 33
#define SeTimeZonePrivilege 34
#define SeCreateSymbolicLinkPrivilege 35

typedef struct _SeFlags
{
	unsigned long long SeNull : 2;
	unsigned long long CreateTokenPrivilege : 1; // 2 SeCreateTokenPrivilege
	unsigned long long AssignPrimaryTokenPrivilege : 1; // 3 SeAssignPrimaryTokenPrivilege
	unsigned long long LockMemoryPrivilege : 1; // 4 SeLockMemoryPrivilege
	unsigned long long IncreaseQuotaPrivilege : 1; // 5 SeIncreaseQuotaPrivilege
	unsigned long long MachineAccountPrivilege : 1; // 6 SeMachineAccountPrivilege
	unsigned long long TcbPrivilege : 1; // 7 SeTcbPrivilege
	unsigned long long SecurityPrivilege : 1; // 8 SeSecurityPrivilege
	unsigned long long TakeOwnershipPrivilege : 1; // 9 SeTakeOwnershipPrivilege
	unsigned long long LoadDriverPrivilege : 1; // 10 SeLoadDriverPrivilege
	unsigned long long SystemProfilePrivilege : 1; // 11 SeSystemProfilePrivilege
	unsigned long long SystemtimePrivilege : 1; // 12 SeSystemtimePrivilege
	unsigned long long ProfileSingleProcessPrivilege : 1; // 13 SeProfileSingleProcessPrivilege
	unsigned long long IncreaseBasePriorityPrivilege : 1; // 14 SeIncreaseBasePriorityPrivilege
	unsigned long long CreatePagefilePrivilege : 1; // 15 SeCreatePagefilePrivilege
	unsigned long long CreatePermanentPrivilege : 1; // 16 SeCreatePermanentPrivilege
	unsigned long long BackupPrivilege : 1; // 17 SeBackupPrivilege
	unsigned long long RestorePrivilege : 1; // 18 SeRestorePrivilege
	unsigned long long ShutdownPrivilege : 1; // 19 SeShutdownPrivilege
	unsigned long long DebugPrivilege : 1; // 20 SeDebugPrivilege
	unsigned long long AuditPrivilege : 1; // 21 SeAuditPrivilege
	unsigned long long SystemEnvironmentPrivilege : 1; // 22 SeSystemEnvironmentPrivilege
	unsigned long long ChangeNotifyPrivilege : 1; // 23 SeChangeNotifyPrivilege
	unsigned long long RemoteShutdownPrivilege : 1; // 24 SeRemoteShutdownPrivilege
	unsigned long long UndockPrivilege : 1; // 25 SeUndockPrivilege
	unsigned long long SyncAgentPrivilege : 1; // 26 SeSyncAgentPrivilege
	unsigned long long EnableDelegationPrivilege : 1; // 27 SeEnableDelegationPrivilege
	unsigned long long ManageVolumePrivilege : 1; // 28 SeManageVolumePrivilege
	unsigned long long ImpersonatePrivilege : 1; // 29 SeImpersonatePrivilege
	unsigned long long CreateGlobalPrivilege : 1; // 30 SeCreateGlobalPrivilege
	unsigned long long TrustedCredManAccessPrivilege : 1; // 31 SeTrustedCredManAccessPrivilege
	unsigned long long RelabelPrivilege : 1; // 32 SeRelabelPrivilege
	unsigned long long IncreaseWorkingSetPrivilege : 1; // 33 SeIncreaseWorkingSetPrivilege
	unsigned long long TimeZonePrivilege : 1; // 34 SeTimeZonePrivilege
	unsigned long long CreateSymbolicLinkPrivilege : 1; // 35 SeCreateSymbolicLinkPrivilege
} SeFlags, * PSeFlags;

typedef struct _SEP_TOKEN_PRIVILEGES
{
	SeFlags Present;
	SeFlags Enabled;
	SeFlags EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, * PSEP_TOKEN_PRIVILEGES;

typedef struct _SmallToken
{
	TOKEN_SOURCE TokenSource;
	LUID TokenID;
	LUID AuthenticationID;
	LUID ParentTokenID;
	LARGE_INTEGER ExperationTime;
	PERESOURCE TokenLock;
	LUID ModifiedID;
	SEP_TOKEN_PRIVILEGES Priviliges;
} SmallToken, * PSmallToken;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;         // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,             // obsolete...delete
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformation = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	MaxSystemInfoClass = 82  // MaxSystemInfoClass should always be the last enum

} SYSTEM_INFORMATION_CLASS;

typedef struct _IDINFO
{
	USHORT	wGenConfig;
	USHORT	wNumCyls;
	USHORT	wReserved;
	USHORT	wNumHeads;
	USHORT	wBytesPerTrack;
	USHORT	wBytesPerSector;
	USHORT	wNumSectorsPerTrack;
	USHORT	wVendorUnique[3];
	CHAR	sSerialNumber[20];
	USHORT	wBufferType;
	USHORT	wBufferSize;
	USHORT	wECCSize;
	CHAR	sFirmwareRev[8];
	CHAR	sModelNumber[40];
	USHORT	wMoreVendorUnique;
	USHORT	wDoubleWordIO;
	struct {
		USHORT	Reserved : 8;
		USHORT	DMA : 1;
		USHORT	LBA : 1;
		USHORT	DisIORDY : 1;
		USHORT	IORDY : 1;
		USHORT	SoftReset : 1;
		USHORT	Overlap : 1;
		USHORT	Queue : 1;
		USHORT	InlDMA : 1;
	} wCapabilities;
	USHORT	wReserved1;
	USHORT	wPIOTiming;
	USHORT	wDMATiming;
	struct {
		USHORT	CHSNumber : 1;
		USHORT	CycleNumber : 1;
		USHORT	UnltraDMA : 1;
		USHORT	Reserved : 13;
	} wFieldValidity;
	USHORT	wNumCurCyls;
	USHORT	wNumCurHeads;
	USHORT	wNumCurSectorsPerTrack;
	USHORT	wCurSectorsLow;
	USHORT	wCurSectorsHigh;
	struct {
		USHORT	CurNumber : 8;
		USHORT	Multi : 1;
		USHORT	Reserved : 7;
	} wMultSectorStuff;
	ULONG	dwTotalSectors;
	USHORT	wSingleWordDMA;
	struct {
		USHORT	Mode0 : 1;
		USHORT	Mode1 : 1;
		USHORT	Mode2 : 1;
		USHORT	Reserved1 : 5;
		USHORT	Mode0Sel : 1;
		USHORT	Mode1Sel : 1;
		USHORT	Mode2Sel : 1;
		USHORT	Reserved2 : 5;
	} wMultiWordDMA;
	struct {
		USHORT	AdvPOIModes : 8;
		USHORT	Reserved : 8;
	} wPIOCapacity;
	USHORT	wMinMultiWordDMACycle;
	USHORT	wRecMultiWordDMACycle;
	USHORT	wMinPIONoFlowCycle;
	USHORT	wMinPOIFlowCycle;
	USHORT	wReserved69[11];
	struct {
		USHORT	Reserved1 : 1;
		USHORT	ATA1 : 1;
		USHORT	ATA2 : 1;
		USHORT	ATA3 : 1;
		USHORT	ATA4 : 1;
		USHORT	ATA5 : 1;
		USHORT	ATA6 : 1;
		USHORT	ATA7 : 1;
		USHORT	ATA8 : 1;
		USHORT	ATA9 : 1;
		USHORT	ATA10 : 1;
		USHORT	ATA11 : 1;
		USHORT	ATA12 : 1;
		USHORT	ATA13 : 1;
		USHORT	ATA14 : 1;
		USHORT	Reserved2 : 1;
	} wMajorVersion;
	USHORT	wMinorVersion;
	USHORT	wReserved82[6];
	struct {
		USHORT	Mode0 : 1;
		USHORT	Mode1 : 1;
		USHORT	Mode2 : 1;
		USHORT	Mode3 : 1;
		USHORT	Mode4 : 1;
		USHORT	Mode5 : 1;
		USHORT	Mode6 : 1;
		USHORT	Mode7 : 1;
		USHORT	Mode0Sel : 1;
		USHORT	Mode1Sel : 1;
		USHORT	Mode2Sel : 1;
		USHORT	Mode3Sel : 1;
		USHORT	Mode4Sel : 1;
		USHORT	Mode5Sel : 1;
		USHORT	Mode6Sel : 1;
		USHORT	Mode7Sel : 1;
	} wUltraDMA;
	USHORT	wReserved89[167];
} IDINFO, *PIDINFO;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID           DllBase;
	PVOID           Entrypoint;
	ULONG           SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB_LDR_DATA
{
	ULONG       Length;
	UCHAR       Initialized;
	PVOID       SsHandle;
	LIST_ENTRY  InLoadOrderModuleList;
	LIST_ENTRY  InMemoryOrderModuleList;
	LIST_ENTRY  InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
	BOOLEAN                         InheritedAddressSpace;
	BOOLEAN                         ReadImageFileExecOptions;
	BOOLEAN                         BeingDebugged;
	BOOLEAN                         BitField;
	HANDLE                          Mutant;
	PVOID                           ImageBaseAddress;
	PPEB_LDR_DATA                   Ldr;
	PRTL_USER_PROCESS_PARAMETERS    ProcessParameters;
	PVOID                           SubSystemData;
	PVOID                           ProcessHeap;
	PVOID                           FastPebLock;
} PEB, *PPEB;

typedef struct _ModuleEntry
{
	void * ModuleBase;
	unsigned long ModuleSize;
	char ModuleName[MAX_PATH];
	char ModulePath[MAX_PATH];
} ModuleEntry, *PModuleEntry;

typedef struct _MMUNLOADED_DRIVER
{
	UNICODE_STRING Name;
	PVOID StartAddress;
	PVOID EndAddress;
	LARGE_INTEGER CurrentTime;
} MMUNLOADED_DRIVER, *PMMUNLOADED_DRIVER;

typedef struct _MMVAD_SHORT
{
	struct _RTL_BALANCED_NODE VadNode;
	unsigned long StartingVpn;
	unsigned long EndingVpn;
	unsigned char StartingVpnHigh;
	unsigned char EndingVpnHigh;
	unsigned char CommitChargeHigh;
	unsigned char SpareNT64VadUChar;
	long ReferenceCount;
	union
	{
		struct
		{
			unsigned __int64 Locked : 1;
			unsigned __int64 Waiting : 1;
			unsigned __int64 Waking : 1;
			unsigned __int64 MultipleShared : 1;
			unsigned __int64 Shared : 60;
		};
		unsigned __int64 Value;
		void * Ptr;
	};
	union
	{
		unsigned long LongFlags;
		struct
		{
			unsigned long VadType : 3;
			unsigned long Protection : 5;
			unsigned long PreferredNode : 6;
			unsigned long NoChange : 1;
			unsigned long PrivateMemory : 1;
			unsigned long Teb : 1;
			unsigned long PrivateFixup : 1;
			unsigned long ManySubsections : 1;
			unsigned long Spare : 12;
			unsigned long DeleteInProgress : 1;
		};
	};
	union
	{
		unsigned long LongFlags1;
		struct
		{
			unsigned long CommitCharge : 31;
			unsigned long MemCommit : 1;
		};
	};
	struct _MI_VAD_EVENT_BLOCK * EventList;
} MMVAD_SHORT, *PMMVAD_SHORT;

typedef struct _MMVAD
{
	struct _MMVAD_SHORT Core;
	union
	{
		unsigned long LongFlags2;
		struct
		{
			unsigned long FileOffset : 24;
			unsigned long Large : 1;
			unsigned long TrimBehind : 1;
			unsigned long Inherit : 1;
			unsigned long CopyOnWrite : 1;
			unsigned long NoValidationNeeded : 1;
			unsigned long Spare : 3; 
		};
	};
	unsigned long pad0;
	struct _SUBSECTION * Subsection;
	struct _MMPTE * FirstPrototypePte;
	struct _MMPTE * LastContiguousPte;
	struct _LIST_ENTRY ViewLinks;
	struct _EPROCESS * VadsProcess;
	union
	{
		struct
		{
			unsigned __int64 Length : 12;
			unsigned __int64 Vpn : 52;
		};
		struct _MMEXTEND_INFO * ExtendedInfo;
	};
	struct _FILE_OBJECT * FileObject;
} MMVAD, *PMMVAD;

typedef struct _MM_AVL_TABLE
{
	PAVL_TREE BalancedRoot;
	void* VadHint;
	unsigned char VadCount;
	unsigned char VadPhysicalPages;
	unsigned char VadPhysicalPagesLimit;
} MM_AVL_TABLE, *PMM_AVL_TABLE;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

typedef void (*PKNORMAL_ROUTINE)
(
	PVOID  NormalContext,
	PVOID  SystemArgument1,
	PVOID  SystemArgument2
);

typedef void (*PKKERNEL_ROUTINE)
(
	struct _KAPC * Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
);

typedef void (*PKRUNDOWN_ROUTINE)
(
	struct _KAPC* Apc
);


struct _OBJECT_TYPE_INITIALIZER
{
	USHORT Length;
	union
	{
		USHORT ObjectTypeFlags;
		struct
		{
			UCHAR CaseInsensitive : 1;
			UCHAR UnnamedObjectsOnly : 1;
			UCHAR UseDefaultObject : 1;
			UCHAR SecurityRequired : 1;
			UCHAR MaintainHandleCount : 1;
			UCHAR MaintainTypeList : 1;
			UCHAR SupportsObjectCallbacks : 1;
			UCHAR CacheAligned : 1;
			UCHAR UseExtendedParameters : 1;
			UCHAR Reserved : 7;
		};
	};
	ULONG ObjectTypeCode;
	ULONG InvalidAttributes;
	struct _GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	ULONG RetainAccess;
	enum _POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	VOID(*DumpProcedure)(VOID* arg1, struct _OBJECT_DUMP_CONTROL* arg2);
	LONG(*OpenProcedure)(enum _OB_OPEN_REASON arg1, CHAR arg2, struct _EPROCESS* arg3, VOID* arg4, ULONG* arg5, ULONG arg6);
	VOID(*CloseProcedure)(struct _EPROCESS* arg1, VOID* arg2, ULONGLONG arg3, ULONGLONG arg4);
	VOID(*DeleteProcedure)(VOID* arg1);
	union
	{
		LONG(*ParseProcedure)(VOID* arg1, VOID* arg2, struct _ACCESS_STATE* arg3, CHAR arg4, ULONG arg5, struct _UNICODE_STRING* arg6, struct _UNICODE_STRING* arg7, VOID* arg8, struct _SECURITY_QUALITY_OF_SERVICE* arg9, VOID** arg10);
		LONG(*ParseProcedureEx)(VOID* arg1, VOID* arg2, struct _ACCESS_STATE* arg3, CHAR arg4, ULONG arg5, struct _UNICODE_STRING* arg6, struct _UNICODE_STRING* arg7, VOID* arg8, struct _SECURITY_QUALITY_OF_SERVICE* arg9, struct _OB_EXTENDED_PARSE_PARAMETERS* arg10, VOID** arg11);
	};
	LONG(*SecurityProcedure)(VOID* arg1, enum _SECURITY_OPERATION_CODE arg2, ULONG* arg3, VOID* arg4, ULONG* arg5, VOID** arg6, enum _POOL_TYPE arg7, struct _GENERIC_MAPPING* arg8, CHAR arg9);
	LONG(*QueryNameProcedure)(VOID* arg1, UCHAR arg2, struct _OBJECT_NAME_INFORMATION* arg3, ULONG arg4, ULONG* arg5, CHAR arg6);
	UCHAR(*OkayToCloseProcedure)(struct _EPROCESS* arg1, VOID* arg2, VOID* arg3, CHAR arg4);
	ULONG WaitObjectFlagMask;
	USHORT WaitObjectFlagOffset;
	USHORT WaitObjectPointerOffset;
};

#undef EX_PUSH_LOCK
#undef PEX_PUSH_LOCK

typedef struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;
			ULONGLONG Waiting : 1;
			ULONGLONG Waking : 1;
			ULONGLONG MultipleShared : 1;
			ULONGLONG Shared : 60;
		};
		ULONGLONG Value;
		void* Ptr;
	};
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

typedef struct _OBJECT_TYPE
{
	struct _LIST_ENTRY TypeList;
	struct _UNICODE_STRING Name;
	void* DefaultObject;
	UCHAR Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	struct _OBJECT_TYPE_INITIALIZER TypeInfo;
	struct _EX_PUSH_LOCK TypeLock;
	ULONG Key;
	struct _LIST_ENTRY CallbackList;
} OBJECT_TYPE, *POBJECT_TYPE;

typedef struct _OB_CALLBACK
{
	LIST_ENTRY ListEntry;
	OB_OPERATION Operation;
	void* RegistrationHandle;
	POBJECT_TYPE ObjectType;
	POB_PRE_OPERATION_CALLBACK PreOperation;
	POB_POST_OPERATION_CALLBACK PostOperation;
} OB_CALLBACK, * POB_CALLBACK;

typedef struct _CM_CALLBACK
{
	LIST_ENTRY ListEntry;
	unsigned long Unknown;
	unsigned long Unknown0;
	LARGE_INTEGER Cookie;
	void* Context;
	PEX_CALLBACK_FUNCTION Function;
	unsigned short AltitudeSize;
	unsigned short AltitudeStart;
	wchar_t* Altitude;
	LIST_ENTRY ListEntry2;
} CM_CALLBACK, *PCM_CALLBACK;

typedef struct _PS_CALLBACK
{
	EX_PUSH_LOCK PushLock;
	void* Function;
	unsigned long FunctionType;
} PS_CALLBACK, *PPS_CALLBACK;

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess
(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

extern "C"
NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

extern "C"
NTKERNELAPI
NTSTATUS
IoCreateDriver
(
	PUNICODE_STRING DriverName,
	PDRIVER_INITIALIZE InitializationFunction
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory
(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	SIZE_T *NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
);

extern "C"
NTSYSAPI
NTSTATUS
ZwQuerySystemInformation
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	ULONG *ReturnLength
);

extern "C"
NTSYSAPI
NTSTATUS NTAPI ObReferenceObjectByName
(
	PUNICODE_STRING ObjectPath,
	ULONG Attributes,
	PACCESS_STATE PassedAccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext,
	PVOID *ObjectPtr
);


extern "C"
NTKERNELAPI
PPEB
NTAPI
PsGetProcessPeb
(
	PEPROCESS Process
);

extern "C"
NTKERNELAPI
const char *
__fastcall
PsGetProcessImageFileName
(
	PEPROCESS Process
);

extern "C"
NTKERNELAPI
BOOLEAN
__fastcall
KeIsAttachedProcess
(
);

extern "C"
NTKERNELAPI
PVOID
NTAPI
RtlFindExportedRoutineByName
(
	PVOID ImageBase,
	PCCH RoutineName
);

extern "C"
NTKERNELAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject
(
	HANDLE  DirectoryHandle,
	PVOID   Buffer,
	ULONG   Length,
	BOOLEAN ReturnSingleEntry,
	BOOLEAN RestartScan,
	PULONG  Context,
	PULONG  ReturnLength
);

extern "C"
NTKERNELAPI
NTSTATUS
NTAPI
ZwOpenProcessToken
(
	HANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	PHANDLE TokenHandle
);

extern "C"
NTKERNELAPI
NTSTATUS
NTAPI
ZwAdjustPrivilegesToken
(
	HANDLE TokenHandle,
	BOOLEAN DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	ULONG BufferLength,
	_Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
	_Out_ _When_(PreviousState == NULL, _Out_opt_) PULONG ReturnLength
);

extern "C"
NTKERNELAPI
NTSTATUS
SeConvertStringSecurityDescriptorToSecurityDescriptor
(
	wchar_t * StringSecurityDescriptor,
	DWORD StringSDRevision,
	PSECURITY_DESCRIPTOR * SecurityDescriptor,
	PULONG SecurityDescriptorSize
);

extern "C"
NTKERNELAPI
void
KeInitializeApc
(
	PRKAPC Apc,
	PRKTHREAD Thread,
	KAPC_ENVIRONMENT Environment,
	PKKERNEL_ROUTINE KernelRoutine,
	PKRUNDOWN_ROUTINE RundownRoutine,
	PKNORMAL_ROUTINE NormalRoutine,
	KPROCESSOR_MODE ApcMode,
	PVOID NormalContext
);

extern "C"
NTKERNELAPI
BOOLEAN
FASTCALL
KeInsertQueueApc
(
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
);

extern "C"
NTSTATUS
PsGetContextThread
(
	PETHREAD Thread,
	PCONTEXT ThreadContext,
	KPROCESSOR_MODE Mode
);

extern "C"
void
ExReleasePushLockEx
(
	PULONGLONG PushLock,
	ULONG Flags
);

extern "C"
void*
PsGetThreadWin32Thread
(
	PETHREAD Thread
);

extern "C"
NTSTATUS
DbgkLkmdRegisterCallback
(
	void* Function,
	unsigned long long Unknown,
	unsigned long Unknown1
);

extern "C"
NTSTATUS
DbgkLkmdUnregisterCallback
(
	void* Function
);

extern "C"
extern __declspec(dllimport) PEPROCESS PsInitialSystemProcess;

extern "C"
extern __declspec(dllimport) PMMUNLOADED_DRIVER MmUnloadedDrivers;

extern "C"
extern __declspec(dllimport) PLDR_DATA_TABLE_ENTRY PsLoadedModuleList;

extern "C"
extern __declspec(dllimport) POBJECT_TYPE * IoDriverObjectType;

extern "C"
extern __declspec(dllimport) POBJECT_TYPE * MmSectionObjectType;

extern "C"
extern __declspec(dllimport) POBJECT_TYPE * IoDeviceObjectType;

#endif