#pragma once
#ifndef BOTH_PEMapper_HEADER_INCLUDED
#define BOTH_PEMapper_HEADER_INCLUDED

#include "GeneralErrors.h"

typedef GeneralErrorCast(*GET_LIBRARY_PE_ADDRESS)(const char * PEName, void ** PEBuffer, void * Reserved);
typedef GeneralErrorCast(*GET_PE_EXPORT)(void * PEBuffer, const char * Export, void ** ExportAddress, void * Reserved);

static GeneralErrorCast MapImageSections(const void * PEBuffer, void * MapingAddress)
{
	if (!PEBuffer)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_PEMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	IMAGE_DOS_HEADER * DosHeader;
	IMAGE_NT_HEADERS * NTHeaders;
	IMAGE_FILE_HEADER * FileHeader;
	IMAGE_SECTION_HEADER * SectionHeader;

	DosHeader = (IMAGE_DOS_HEADER*)PEBuffer;
	NTHeaders = (IMAGE_NT_HEADERS*)((char*)PEBuffer + DosHeader->e_lfanew);
	FileHeader = &NTHeaders->FileHeader;

	SectionHeader = IMAGE_FIRST_SECTION(NTHeaders);
	for (unsigned long i = 0; i < FileHeader->NumberOfSections; i++, SectionHeader++)
		memcpy((char*)MapingAddress + SectionHeader->VirtualAddress, (char*)PEBuffer + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);
	return STATUS_SUCCESS;
}

static GeneralErrorCast RelocateImage(const void * PEBuffer, void * MappedPEBuffer, void * RelocationAddress)
{
	if (!PEBuffer)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_PEMAPPER, STATUS_INVALID_PARAMETER_1) | 1;

	void * RelocationDelta;

	IMAGE_DOS_HEADER * DosHeader;
	IMAGE_NT_HEADERS * NTHeaders;
	IMAGE_OPTIONAL_HEADER * OptionalHeader;
	IMAGE_BASE_RELOCATION * BaseRelocation;

	DosHeader = (IMAGE_DOS_HEADER*)PEBuffer;
	NTHeaders = (IMAGE_NT_HEADERS*)((char*)PEBuffer + DosHeader->e_lfanew);
	OptionalHeader = &NTHeaders->OptionalHeader;

	RelocationDelta = (char*)RelocationAddress - OptionalHeader->ImageBase;
	if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		BaseRelocation = (IMAGE_BASE_RELOCATION*)((char*)MappedPEBuffer + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (BaseRelocation->VirtualAddress)
		{
			unsigned short * RelativeInfo = (unsigned short*)(BaseRelocation + 1);
			for (unsigned long i = 0; i < ((BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(unsigned short)); i++, RelativeInfo++)
			{
				if (/*((*RelativeInfo) >> 0x0C) == IMAGE_REL_BASED_HIGHLOW || */((*RelativeInfo) >> 0x0C) == IMAGE_REL_BASED_DIR64)
				{
					unsigned long long * Patch = (unsigned long long*)((char*)MappedPEBuffer + BaseRelocation->VirtualAddress + (*RelativeInfo & 0xFFF));
					*Patch += (unsigned long long)RelocationDelta;
				}
			}
			BaseRelocation = (IMAGE_BASE_RELOCATION*)((char*)BaseRelocation + BaseRelocation->SizeOfBlock);
		}
	}
	return STATUS_SUCCESS;
}

static GeneralErrorCast FixImageImports(const void * PEBuffer, void * MappedPEBuffer, FunctionCallBack PEBufferFunction, FunctionCallBack ExportFunction)
{
	if (!PEBuffer)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_PEMAPPER, STATUS_INVALID_PARAMETER_1) | 1;
	if (!PEBufferFunction.Function)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_PEMAPPER, STATUS_INVALID_PARAMETER_2) | 1;
	if (!ExportFunction.Function)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_PEMAPPER, STATUS_INVALID_PARAMETER_3) | 1;

	IMAGE_DOS_HEADER * DosHeader;
	IMAGE_NT_HEADERS * NTHeaders;
	IMAGE_OPTIONAL_HEADER * OptionalHeader;
	IMAGE_IMPORT_DESCRIPTOR * ImportDescriptor;

	GeneralError Error;

	DosHeader = (IMAGE_DOS_HEADER*)PEBuffer;
	NTHeaders = (IMAGE_NT_HEADERS*)((char*)PEBuffer + DosHeader->e_lfanew);
	OptionalHeader = &NTHeaders->OptionalHeader;

	if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((char*)MappedPEBuffer + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		for (; ImportDescriptor->Name; ImportDescriptor++)
		{
			IMAGE_IMPORT_BY_NAME * ImportByName;
			unsigned long long * OriginalFirstThunk;
			unsigned long long * FirstThunk;
			char * LibraryName;
			void * LibraryBase;
			void * ExportBase;

			LibraryName = (char*)((char*)MappedPEBuffer + ImportDescriptor->Name);
			Error.ErrorValue = ((GET_LIBRARY_PE_ADDRESS)PEBufferFunction.Function)(LibraryName, &LibraryBase, PEBufferFunction.Reserved);
			if (!NT_SUCCESS(Error.NTStatus))
				return Error.ErrorValue;

			OriginalFirstThunk = (unsigned long long*)((char*)MappedPEBuffer + ImportDescriptor->OriginalFirstThunk);
			FirstThunk = (unsigned long long*)((char*)MappedPEBuffer + ImportDescriptor->FirstThunk);

			if (!OriginalFirstThunk)
				OriginalFirstThunk = FirstThunk;

			for (; *OriginalFirstThunk; OriginalFirstThunk++, FirstThunk++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*OriginalFirstThunk))
				{
					ExportBase = ((void*)*FirstThunk);

					Error.ErrorValue = ((GET_PE_EXPORT)ExportFunction.Function)(LibraryBase, (const char*)(*OriginalFirstThunk & 0xFFFF), &ExportBase, ExportFunction.Reserved);
					if (!NT_SUCCESS(Error.NTStatus))
						return Error.ErrorValue;

					*FirstThunk = (unsigned long long)ExportBase;
				}
				else
				{
					ExportBase = ((void*)*FirstThunk);

					ImportByName = (IMAGE_IMPORT_BY_NAME*)((char*)MappedPEBuffer + (*OriginalFirstThunk));
					Error.ErrorValue = ((GET_PE_EXPORT)ExportFunction.Function)(LibraryBase, ImportByName->Name, &ExportBase, ExportFunction.Reserved);
					if (!NT_SUCCESS(Error.NTStatus))
						return Error.ErrorValue;

					*FirstThunk = (unsigned long long)ExportBase;
				}
			}
		}
	}
	return STATUS_SUCCESS;
}

#endif