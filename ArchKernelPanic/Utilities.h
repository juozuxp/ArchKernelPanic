#pragma once

#define AKP_UTILITIES 0

static GeneralErrorCast FindModuleByName(const char* Name, PLDR_DATA_TABLE_ENTRY* Module)
{
	PLDR_DATA_TABLE_ENTRY CurrentEntry;
	
	CurrentEntry = PsLoadedModuleList;
	do
	{
		const wchar_t* RunLdrName;
		const char* RunName;

		RunName = Name;
		RunLdrName = CurrentEntry->BaseDllName.Buffer;
		for (; *RunLdrName && *RunName; RunLdrName++, RunName++)
		{
			wchar_t First;
			wchar_t Second;

			First = *RunLdrName;
			if (First >= L'A' && First <= L'Z')
				First += L'a'- L'A';

			Second = *RunName;
			if (Second >= L'A' && Second <= L'Z')
				Second += L'a' - L'A';

			if (First != Second)
				break;
		}

		if (!*RunName && !*RunLdrName)
		{
			*Module = CurrentEntry;
			return STATUS_SUCCESS;
		}

		CurrentEntry = CONTAINING_RECORD(CurrentEntry->InLoadOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	} while (PsLoadedModuleList != CurrentEntry);

	return GENERAL_ERROR_ASSEMBLE(AKP_UTILITIES, STATUS_NOT_FOUND);
}