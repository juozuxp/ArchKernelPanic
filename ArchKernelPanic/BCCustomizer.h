#pragma once
#include "../GeneralHeaders/both/MemoryExplorer.h"
#include "../GeneralHeaders/both/PEDisector.h"
#include "Utilities.h"

#define AKP_BCCUSTOMIZER 0

#define CONVERT_COLOR_8_6(Color) ((unsigned char)((((float)(Color)) / ((float)(1 << 8))) * ((float)(1 << 6))))
#define CONVERT_COLORS_8_6(Colors) ((CONVERT_COLOR_8_6(((Colors) >> 16) & ((1 << 8) - 1)) << 16) | (CONVERT_COLOR_8_6(((Colors) >> 8) & ((1 << 8) - 1)) << 8) | CONVERT_COLOR_8_6((Colors) & ((1 << 8) - 1)))

#define WRITE_PROTECT_BIT_CR0 16

typedef struct _BCScreenData
{
	unsigned long* ColorPallet;								/* 
															   Color pallet of 16, 6 bit colors (XRGB format)
															   The colors assigned to the pallet remap as follows:

															   FourBitPalette[16]:
															   00000000, 001173AA, 00227DB0, 003387B6,
															   004491BC, 00559BC2, 0066A5C8, 0077AFCE,
															   0088B9D4, 0099C3DA, 00AACDE0, 00BBD7E6,
															   00CCE1EC, 00DDEBF2, 00EEF5F8, 00FFFFFF
															*/

	UNICODE_STRING* DeviceNeedsToRestart;					// "Your device ran into a problem and needs to restart." Message
	UNICODE_STRING* CollectingSomeErrorInfoRestartForYou;	// "We're just collecting some error info, and then we'll restart for you." Message
	UNICODE_STRING* CollectingSomeErrorInfoRestart;			// "We're just collecting some error info, and then you can restart." Message
	UNICODE_STRING* RestartForYou;							// "We'll restart for you." Message
	UNICODE_STRING* YouCanRestart;							// "You can restart." Message
	UNICODE_STRING* CallSupport;							// "If you call a support person, give them this info:" Message
	UNICODE_STRING* WhatFailed;								// "What failed:" Message
	UNICODE_STRING* StopCode;								// "Stop Code:" Message
	UNICODE_STRING* ForMoreInfoVisit;						// "For more information about this issue and possible fixes, visit " Message
	UNICODE_STRING* StopCodeLink;							// "https://www.windows.com/stopcode" Message
	UNICODE_STRING* InsiderBuildProblem;					// "Your Windows Insider Build ran into a problem and needs to restart." Message
	UNICODE_STRING* ReleasePowerButton;						// "Please release the power button." Message
	UNICODE_STRING* JustNeedAFewSecondsShutdown;			// "We just need a few more seconds to shut down." Message
	UNICODE_STRING* NowSafePowerOff;						// "It is now safe to power off the system." Message
	UNICODE_STRING* PercentCompleteAfter;					// "% complete" Message, After %number% complete
	UNICODE_STRING* PercentCompleteAfter_0;					// "% complete" Message, After %number% complete
	UNICODE_STRING* PercentCompleteBefore;					// Before %number% complete
	UNICODE_STRING* PercentCompleteBefore_0;				// Before %number% complete
	UNICODE_STRING* FrownyFace;								// ":(", located in .rdata of ntoskrnl.exe, watch out for patchguard with this one
} BCScreenData, *PBCScreenData;

static GeneralErrorCast BCCAssignColorPallet8BitColor(BCScreenData* Data, unsigned long* ColorPallet)
{
	if (!Data)
		return GENERAL_ERROR_ASSEMBLE(AKP_BCCUSTOMIZER, STATUS_INVALID_PARAMETER_1);

	if (!ColorPallet)
		return GENERAL_ERROR_ASSEMBLE(AKP_BCCUSTOMIZER, STATUS_INVALID_PARAMETER_2);

	for (unsigned char i = 0; i < 16; i++)
		Data->ColorPallet[i] = CONVERT_COLORS_8_6(ColorPallet[i]);

	return STATUS_SUCCESS;
}

static GeneralErrorCast BCCSetString(UNICODE_STRING* BaseOfString, UNICODE_STRING* Override)
{
	if (!BaseOfString)
		return GENERAL_ERROR_ASSEMBLE(AKP_BCCUSTOMIZER, STATUS_INVALID_PARAMETER_1);

	if (!Override)
		return GENERAL_ERROR_ASSEMBLE(AKP_BCCUSTOMIZER, STATUS_INVALID_PARAMETER_2);

	unsigned long long Backup;

	_disable();
	Backup = __readcr0();
	__writecr0(Backup & ~(1 << WRITE_PROTECT_BIT_CR0));

	memcpy(BaseOfString, Override, sizeof(UNICODE_STRING));

	__writecr0(Backup);
	_enable();

	return STATUS_SUCCESS;
}

static GeneralErrorCast BCCInitializeScreenData(BCScreenData* Data)
{
	if (!Data)
		return GENERAL_ERROR_ASSEMBLE(AKP_BCCUSTOMIZER, STATUS_INVALID_PARAMETER_1);

	unsigned char SigBuffer[0x100];
	void* RelativeAddress;

	IMAGE_SECTION_HEADER* Section;
	PLDR_DATA_TABLE_ENTRY Module;

	GeneralError Error;

	memset(Data, 0, sizeof(BCScreenData));

	Error.ErrorValue = FindModuleByName("BasicDisplay.sys", &Module);
	if (NT_SUCCESS(Error.NTStatus))
	{
		Error.ErrorValue = FindSectionByName(Module->DllBase, ".text", &Section);
		if (NT_SUCCESS(Error.NTStatus))
		{
			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? E8 ? ? ? ? 44 8B C0", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->ColorPallet = (unsigned long*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}
		}
	}

	Error.ErrorValue = FindModuleByName("ntoskrnl.exe", &Module); // Alternatively reverse string search could be done, where string would be located within the module, then a reference would be found that would have it's description in a UNICODE_STRING format
	if (NT_SUCCESS(Error.NTStatus))
	{
		Error.ErrorValue = FindSectionByName(Module->DllBase, ".text", &Section);
		if (NT_SUCCESS(Error.NTStatus))
		{
			Error.ErrorValue = ConvertIDASigToDescSig("4C 8D 15 ? ? ? ? 03 0D ? ? ? ? 41 8B 54 F7", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->DeviceNeedsToRestart = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 15 ? ? ? ? 85 C0 48 0F 44 CA", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->CollectingSomeErrorInfoRestartForYou = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? EB ? 48 8D 0D", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->CollectingSomeErrorInfoRestart = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? 48 8D 15 ? ? ? ? 85 C0", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->RestartForYou = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? EB ? 48 8D 0D ? ? ? ? 48 8D 15", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->YouCanRestart = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 05 ? ? ? ? 49 89 44 24 ? 41 8B C7", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->CallSupport = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? 41 03 D7", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->WhatFailed = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? 44 03 FB", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->StopCode = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? 4C 89 6C 24", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->ForMoreInfoVisit = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? 44 8B CE E8 ? ? ? ? 41 8B 4C FF", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->StopCodeLink = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? F7 05 ? ? ? ? 00 00 00 10", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->InsiderBuildProblem = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? EB ? 41 03 D1", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->ReleasePowerButton = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? EB ? 41 84 FE", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->JustNeedAFewSecondsShutdown = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? 44 8B CE E8 ? ? ? ? 48 8B 74 24", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->NowSafePowerOff = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? 48 0F 45 C8 48 8D 15", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->PercentCompleteAfter = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 05 ? ? ? ? 83 FB 01 48 8D 0D", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->PercentCompleteAfter_0 = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? 48 0F 45 C8 E8 ? ? ? ? 8D 46", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->PercentCompleteBefore = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 05 ? ? ? ? 89 75 ? 83 FB 01", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->PercentCompleteBefore_0 = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}

			Error.ErrorValue = ConvertIDASigToDescSig("48 8D 0D ? ? ? ? 3B EF 75 ? 48 8D 0D", SigBuffer, 0);
			if (NT_SUCCESS(Error.NTStatus))
			{
				Error.ErrorValue = ScanMemoryDescSig(((unsigned char*)Module->DllBase) + Section->VirtualAddress, Section->Misc.VirtualSize, SigBuffer, (void**)&RelativeAddress);
				if (NT_SUCCESS(Error.NTStatus))
					Data->FrownyFace = (UNICODE_STRING*)(((unsigned char*)RelativeAddress) + *(long*)(((unsigned char*)RelativeAddress) + 3) + 7);
			}
		}
	}

	return STATUS_SUCCESS;
}

