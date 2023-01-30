#include "utility.h"




PIMAGE_NT_HEADERS get_nt_headers(PVOID pImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pImageBase + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return pNtHeader;
}

DWORD get_image_base(PVOID pImageBase) { // virtual base
	PIMAGE_NT_HEADERS nt_header = get_nt_headers(pImageBase);

	return nt_header->OptionalHeader.ImageBase;
}
DWORD get_section_address(PVOID base, const char* name ) {


	PIMAGE_NT_HEADERS nt_header = get_nt_headers(base);
	WORD num_sections = nt_header->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);



	for (WORD i = 0; i < num_sections; i++) {

		if (!strcmp(name, (char*)section[i].Name))
		{
			
			return section[i].PointerToRawData;
		}
	}

	return 0;
}

DWORD resolve_relative_address(PVOID base, DWORD virtual_add) {

	PIMAGE_NT_HEADERS nt_headers = get_nt_headers(base);

	DWORD virtual_base = get_image_base(base);

	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);

	WORD num_sections = nt_headers->FileHeader.NumberOfSections;

	bool found = false;

	for (WORD i = 0; i < num_sections; i++, section_header++) {
		DWORD section_start = virtual_base + section_header->VirtualAddress;
		DWORD section_end = section_start + section_header->Misc.VirtualSize;
		/*std::cout << "start: " << section_start << std::endl;
		std::cout << "end: " << section_end << std::endl;*/
		/*std::cout << virtual_add << std::endl;*/
		if (virtual_add >= section_start && virtual_add < section_end) {
			found = true;
			break;
		}
	}
	if (!found) {
		//std::cout << "failed to find section" << std::endl;
		return NULL;
	}
	virtual_add -= virtual_base;
	virtual_add -= section_header->VirtualAddress;

	virtual_add += section_header->PointerToRawData;
	virtual_add += (DWORD)base;

	return virtual_add;
}