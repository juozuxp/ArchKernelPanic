#pragma once
#ifndef BOTH_MemoryExplorer_HEADER_INCLUDED
#define BOTH_MemoryExplorer_HEADER_INCLUDED

#include "GeneralErrors.h"

#define CHAR_TO_NUM(Char) (((Char) < 58 && (Char) > 47) ? ((Char) - 48) : (((Char) < 71 && (Char) > 64) ? ((Char) - 65 + 10) : (((Char) < 103 && (Char) > 96) ? ((Char) - 97 + 10) : 0)))
#define BYTE_TO_NUM(Byte) ((CHAR_TO_NUM(Byte[0]) * 16) + CHAR_TO_NUM(Byte[1]))
#define IS_HEX_CHAR(Char) (((Char) > 47 && (Char) < 58) || ((Char) > 64 && (Char) < 71) || ((Char) > 96 && (Char) < 103))

typedef void* DescriptorSig;
typedef const char* IDASig;

static GeneralErrorCast ConvertIDAToBinaryMaskSig(const char * IDASig, unsigned char * SmartSig, unsigned short * SigSize)
{
	if (!IDASig)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_1) | 1;
	if (!SigSize)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_3) | 1;

	unsigned short CurrentSigSize = 0;
	unsigned char * SigAddress = 0;
	unsigned char * MaskAddress = 0;

	if (SmartSig)
	{
		*(unsigned short*)SmartSig = *SigSize;
		SigAddress = SmartSig + *(unsigned short*)(SmartSig) / 8 + (*(unsigned short*)(SmartSig) % 8 ? 1 : 0) + sizeof(unsigned short);
		MaskAddress = SmartSig + sizeof(unsigned short);
	}
	*SigSize = 0;
	while (*IDASig)
	{
		if (*IDASig == '?')
		{
			if (*(IDASig + 1) == '?')
				IDASig++;

			(*SigSize)++;
		}
		else if (IS_HEX_CHAR(*IDASig))
		{
			if (SmartSig)
			{
				MaskAddress[(CurrentSigSize + *SigSize) / 8] |= 1 << ((CurrentSigSize + *SigSize) % 8);
				SigAddress[CurrentSigSize] = BYTE_TO_NUM(IDASig);
			}

			if (IS_HEX_CHAR(*(IDASig + 1)))
				IDASig++;

			CurrentSigSize++;
		}
		IDASig++;
	}

	*SigSize += CurrentSigSize;
	return STATUS_SUCCESS;
}

static GeneralErrorCast ScanMemoryWBinaryMaskSig(void * MemoryDump, unsigned long DumpSize, unsigned char * SmartSig, void ** HitAddress)
{
	if (!MemoryDump)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_1) | 1;
	if (!DumpSize)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_2) | 1;
	if (!SmartSig)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_3) | 1;
	if (!HitAddress)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_4) | 1;

	*HitAddress = 0;

	unsigned short SigSize;
	unsigned short Hits = 0;
	unsigned short SigProgress = 0;
	unsigned char * SigAddress = 0;
	unsigned char * MaskAddress = 0;

	SigSize = *(unsigned short*)SmartSig;
	SigAddress = SmartSig + (SigSize / 8 + (SigSize % 8 ? 1 : 0) + sizeof(unsigned short));
	MaskAddress = SmartSig + sizeof(unsigned short);

	for (unsigned long i = 0; i < DumpSize; i++, MemoryDump = (char*)MemoryDump + 1)
	{
		if (MaskAddress[Hits / 8] & (1 << Hits % 8))
		{
			if (*(unsigned char*)MemoryDump == *(SigAddress + SigProgress))
			{
				Hits++;
				SigProgress++;
			}
			else
			{
				SigProgress = 0;
				Hits = 0;
			}
		}
		else
			Hits++;
		if (Hits == SigSize)
		{
			*HitAddress = (char*)MemoryDump - SigSize + 1;
			return STATUS_SUCCESS;
		}
	}
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_NOT_FOUND) | 1;
}

static GeneralErrorCast ConvertIDAToWORDSig(const char * IDASig, unsigned short * WORDSig, unsigned short * SigSize)
{
	if (!IDASig)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_1) | 1;
	if (!WORDSig)
		if (!SigSize)
			return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_2) | 1;

	if (SigSize)
		*SigSize = 0;

	unsigned short CurrentSigSize = 0;
	while (*IDASig)
	{
		if (*IDASig == '?')
		{
			if (*(IDASig + 1) == '?')
				IDASig++;
			if (WORDSig)
			{
				*WORDSig = 0x100;
				WORDSig++;
			}
			CurrentSigSize++;
		}
		if (IS_HEX_CHAR(*IDASig))
		{
			if (WORDSig)
			{
				*WORDSig = BYTE_TO_NUM(IDASig);
				WORDSig++;
			}
			CurrentSigSize++;
			IDASig++;
		}
		IDASig++;
	}
	*WORDSig = 0xFFFF;
	if (SigSize)
		*SigSize = CurrentSigSize + 1;

	return STATUS_SUCCESS;
}

static GeneralErrorCast ScanMemoryWWORDSig(void * MemoryDump, unsigned long DumpSize, unsigned short * WORDSig, unsigned long * HitVirtAddress)
{
	if (!MemoryDump)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_1) | 1;
	if (!DumpSize)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_2) | 1;
	if (!WORDSig)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_3) | 1;
	if (!HitVirtAddress)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_4) | 1;

	*HitVirtAddress = 0;

	unsigned long Progress = 0;
	unsigned short SigProgress = 0;

	while (Progress < DumpSize)
	{
		if (*WORDSig & 0xFF00)
		{
			SigProgress++;
			WORDSig++;
		}
		else if (*((unsigned char*)MemoryDump) == *((unsigned char*)WORDSig))
		{
			SigProgress++;
			WORDSig++;
		}
		else
		{
			MemoryDump = ((unsigned char*)MemoryDump) - SigProgress;
			Progress -= SigProgress;
			WORDSig -= SigProgress;
			SigProgress = 0;
		}
		if ((*WORDSig & (unsigned short)0xFF00) == (unsigned short)0xFF00)
		{
			*HitVirtAddress = Progress - SigProgress + 1;
			return STATUS_SUCCESS;
		}
		MemoryDump = ((unsigned char*)MemoryDump) + 1;
		Progress++;
	}
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_NOT_FOUND) | 1;
}

static GeneralErrorCast ScanMemoryDescSig(void* Memory, unsigned long MemorySize, DescriptorSig Signature, void** FoundAddress)
{
	if (!Memory)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_1) | 1;

	if (!MemorySize)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_2) | 1;

	if (!Signature)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_3) | 1;

	if (!FoundAddress)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_4) | 1;

	*FoundAddress = 0;

	unsigned long MemoryProgress;
	unsigned long SignatureProgress;

	MemoryProgress = 0;
	SignatureProgress = 0;

	while (*(char*)Signature)
	{
		if (*(char*)Signature < 0)
		{
			MemoryProgress -= *(char*)Signature;
			Memory = (char*)Memory - *(char*)Signature;
		}
		else
		{
			if ((MemoryProgress + *(char*)Signature) > MemorySize)
				return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_NOT_FOUND) | 1;
			if (!memcmp(Memory, (char*)Signature + 1, *(char*)Signature))
			{
				MemoryProgress += *(char*)Signature;
				Memory = (char*)Memory + *(char*)Signature;

				SignatureProgress += *(char*)Signature;
				Signature = (char*)Signature + *(char*)Signature;
			}
			else
			{
				Memory = (char*)Memory - MemoryProgress + 1;
				MemorySize--;
				MemoryProgress = 0;

				Signature = (char*)Signature - SignatureProgress - 1;
				SignatureProgress = -1;
			}
		}
		Signature = (char*)Signature + 1;
		SignatureProgress++;
	}

	*FoundAddress = (char*)Memory - MemoryProgress;
	return STATUS_SUCCESS;
}

static GeneralErrorCast ConvertIDASigToDescSig(IDASig IDASignature, DescriptorSig DescSignature, unsigned long* DescSignatureSize)
{
	if (!IDASignature)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER_1) | 1;
	if (!DescSignature && !DescSignatureSize)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_MEMORYEXPLORER, STATUS_INVALID_PARAMETER) | 1;

	if (DescSignatureSize)
		*DescSignatureSize = 0;

	char Size;

	Size = 0;
	if (DescSignatureSize)
		*DescSignatureSize = 0;

	if (DescSignature)
	{
		for (;*IDASignature != '?' && *IDASignature; IDASignature++)
		{
			if (IS_HEX_CHAR(*IDASignature))
			{
				DescSignature = (char*)DescSignature + 1;
				break;
			}
		}
	}

	while (*IDASignature)
	{
		if (IS_HEX_CHAR(*IDASignature))
		{
			if (Size < 0)
			{
				if (DescSignatureSize)
					*DescSignatureSize += 1;

				if (DescSignature)
				{
					(*(char*)(DescSignature)) = Size;
					DescSignature = ((char*)DescSignature + 2);
				}

				Size = 0;
			}
			else if (Size == 0x7F)
			{
				if (DescSignatureSize)
					*DescSignatureSize += Size + 1;

				if (DescSignature)
				{
					(*((char*)(DescSignature)-Size - 1)) = Size;
					DescSignature = ((char*)DescSignature + 2);
				}
			}

			if (DescSignature)
			{
				(*(unsigned char*)(DescSignature)) = BYTE_TO_NUM(IDASignature);
				DescSignature = (char*)DescSignature + 1;
			}

			Size++;
			IDASignature++;
		}
		else if (*IDASignature == '?')
		{
			if (*(IDASignature + 1) == '?')
				IDASignature++;

			if (Size > 0)
			{
				if (DescSignatureSize)
					*DescSignatureSize += Size + 1;

				if (DescSignature)
					(*((char*)(DescSignature)-Size - 1)) = Size;

				Size = 0;
			}
			else if (Size == ~0x7F)
			{
				if (DescSignatureSize)
					*DescSignatureSize -= Size;

				if (DescSignature)
				{
					(*(char*)(DescSignature)) = Size;
					DescSignature = ((char*)DescSignature + 1);
				}
			}
			Size--;
		}
		IDASignature++;
	}

	if (Size > 0)
	{
		if (DescSignatureSize)
			*DescSignatureSize += Size + 1;

		if (DescSignature)
			(*((char*)(DescSignature) - Size - 1)) = Size;
	}

	if (DescSignatureSize)
		if (*DescSignatureSize)
			*DescSignatureSize += 1;

	if (DescSignature)
		*((unsigned char*)(DescSignature)) = 0;

	return STATUS_SUCCESS;
}

#endif