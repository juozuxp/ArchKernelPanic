#include "../GeneralHeaders/um/Imports.h"
#include "../GeneralHeaders/um/DriverMapper.h"
#include "../GeneralHeaders/um/VulnerableDrivers/Intel.h"

int main()
{
	LoadDriverExA(INTELBinary, sizeof(INTELBinary), "BlueStyle.sys", "StyledScreen"); // this is serious stuff, the functions will MAP (not load) the driver, i.e. it'll bypass signature enforcement, BE CAREFUL this is considered to be very volatile and some antivirus/anticheat software will consider this a threat
	MapDriverByPathA(INTELExecute, "BlueStyle.sys", "ArchKernelPanic.sys", 0, 0);
	UnloadDriverExA("BlueStyle.sys", "StyledScreen");
}