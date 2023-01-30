#pragma once
#include <Windows.h>
#include <iostream>

DWORD get_section_address(PVOID base, const char* name);

DWORD resolve_relative_address(PVOID base, DWORD virtual_add);

DWORD get_image_base(PVOID pImageBase);