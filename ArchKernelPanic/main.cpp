#include "../GeneralHeaders/km/Imports.h"
#include "BCCustomizer.h"

void Unload(PDRIVER_OBJECT Object)
{
}

GeneralErrorCast DriverEntry(PDRIVER_OBJECT Object)
{
	UNICODE_STRING String;
	BCScreenData Data;

	unsigned long Colors[] = { 0x00000000, 0x00FF00FF, 0x00FF00FF, 0x00FF00FF, 0x00FF00FF, 0x00FFFFFF, 0x00FFFFFF, 0x00FFFFFF, 0x00FFFFFF, 0x00FFFFFF, 0x00FFFFFF, 0x00FFFFFF, 0x00FFFFFF, 0x00FFFFFF, 0x00FFFFFF, 0x00FFFFFF };

	if (Object) // check if we have a DRIVER_OBJECT, if not, we got to kernel via manual map
		Object->DriverUnload = Unload;

	BCCInitializeScreenData(&Data);

	String = RTL_CONSTANT_STRING(L"XD");
	BCCSetString(Data.FrownyFace, &String);

	String = RTL_CONSTANT_STRING(L"% Done shitting");
	BCCSetString(Data.PercentCompleteAfter, &String);
	BCCSetString(Data.PercentCompleteAfter_0, &String);

	BCCAssignColorPallet8BitColor(&Data, Colors);

	return STATUS_SUCCESS;
}