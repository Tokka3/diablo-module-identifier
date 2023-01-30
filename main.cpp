#include <iostream>
#include <windows.h>
#include "md5.h"
#include "utility.h"
#include <vector>
#include "colour.hpp"
#include <iomanip>


void PrintData(BYTE* data, int size)
{
	for (size_t i = 0; i < size; i++)
	{
		if (!(i % 8) && i != 0)
			printf("%X\n", data[i]);
		else
			printf("%X ", data[i]);
	}
}

struct _MAIN_SCAN {
	PVOID main_scan_address;
	int main_scan_count;
};

struct VAC_FUNCTION {
	std::vector<_MAIN_SCAN> mainscan_fns;
	std::vector<PVOID> mainscan_ref_fns;
	std::vector<PVOID> sorted_addresses;
	std::string mod_name;
};


VAC_FUNCTION vac_fncs;

// Main scan 1

// Main scan 2

// Main scan 3

// Function that references MainScan 1
std::map<UINT64, std::string> scanhashMap =
{
	//invalid modules
	std::make_pair(0xc0590d2ae24ec3d3, "crash"),

	//fully bypassed modules
	std::make_pair(0xa00dbf237edd5a2f, "hwid"),
	std::make_pair(0xea2af2e2bce3220a, "handle"),
	std::make_pair(0xaab5578e266c1b61, "window"),
	std::make_pair(0x68a58bb36a53a7a4, "filemapping"),

	//unneeded modules
	std::make_pair(0x2f28f009f9674643, "processInfo1"),
	std::make_pair(0xb219318b5e3a74c3, "processInfo2"),
	std::make_pair(0xda4778bb56d2989, "processInfo3"),
	std::make_pair(0xf0f0251921dfd9fa, "modsAndThreads1"),
	std::make_pair(0x6b6eec243d579bae, "modsAndThreads2"),
	std::make_pair(0xb59a2f53422e586e, "memScan"),
	std::make_pair(0x8bded48bbea11906, "moreProcessInfo"),
	std::make_pair(0x4ff1f6019b33fd5f, "queryAndReadMem"),
	std::make_pair(0xfdc2028fa3b8286f, "readMem"),

	//low priority
	std::make_pair(0xb34c2e74f57f4d0a, "SCQUERY"),
	std::make_pair(0xa612337c5223f13a, "SNMP"),
	std::make_pair(0x2153e378b10e88f5, "BOOTREGKEYS"),
	std::make_pair(0x7e14cd062f6edb31, "SERVICEDEVICESTUFF"),
	std::make_pair(0xd3dc7554776447f1, "CPUSTUFF"),

	//wip
	std::make_pair(0xeee57d9442e9d36f, "USN"),
	std::make_pair(0x463a5b2296ae616b, "SYSCALLSTUFF")
};

void log_error(std::string str) {
	std::cout << dye::red(str) << " " << std::hex << GetLastError() << std::endl;
	Sleep(1000);
	exit(0);

}
int main() {

	WIN32_FIND_DATA fd;
	std::string path = "C:\\Users\\admin\\Desktop\\csgo shit\\moduledump\\good dump\\modules\\";
	HANDLE hFind = FindFirstFile(std::string(path + "*.dll").c_str(), &fd);

	if (hFind != INVALID_HANDLE_VALUE) {
		do {


		//	std::cout << dye::green(fd.cFileName) << "\n" << std::endl;
			std::string str_file_name(fd.cFileName);
			vac_fncs.mod_name = fd.cFileName;
			//std::cout << path + str_file_name << std::endl;

			HANDLE file_handle =
				CreateFileA(std::string(path + str_file_name).c_str(),
					GENERIC_READ | GENERIC_WRITE,
					FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
					NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL);

			if (!file_handle) {
				log_error("couldn't get file handle");
			}

			DWORD file_size = GetFileSize(file_handle, NULL);

			PVOID base = VirtualAlloc(NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			//    std::cout << file_size << std::endl;
			if (!ReadFile(file_handle, base, file_size, NULL, NULL)) {
				log_error("failed to read file");
			}

			DWORD text_add = get_section_address(base, ".text");

			if (!text_add) {
				log_error("failed to get text address");
			}

			//  std::cout << ".text add: " << std::hex << text_add << std::endl;
			PDWORD function_list = (PDWORD)((DWORD)base + text_add + 0x4);

			if (!function_list) {
				log_error("failed to get function list");
			}


			// std::cout << "function list add: " << std::hex << function_list << std::endl;

			int main_scan_count = 0; // this is used to identify the next function in order to calculate size

			for (int i = 0; i < 100000000; i++) { // looping through function list

				

				PBYTE function_address = (PBYTE)(function_list[i]);

				if (!function_address) break;

				//std::cout << "function address: " << std::hex << DWORD(function_address) << std::endl;
				function_address = (PBYTE)resolve_relative_address(base, (DWORD)function_address);
			//	PrintData(function_address, 20);
			
				if (!function_address) break;

				PVOID scan_add{};

				for (function_address;; function_address += sizeof(byte)) { // looping through the bytes in each function to check for return

					BYTE curr_byte = *(BYTE*)(function_address);

					if (curr_byte == 0xC7) { // 0xc7 is byte for return address 
					
						function_address -= 5;

						scan_add = *(PVOID*)(function_address + 1);

						scan_add = (PVOID)resolve_relative_address(base, (DWORD)(scan_add));
						//PrintData(function_address, 20);


						if (scan_add) {
							
							main_scan_count++;
							// std::cout << "scan_add found " << std::hex << (DWORD)scan_add << std::endl;
							PVOID mainscan_fnc_add = *(PVOID*)((DWORD)scan_add + 0xC);
							mainscan_fnc_add = (PVOID)resolve_relative_address(base, (DWORD)mainscan_fnc_add);
							//  PrintData((PBYTE)mainscan_fnc_add, 40);
							_MAIN_SCAN add;

							add.main_scan_address = mainscan_fnc_add;

							add.main_scan_count = main_scan_count;

						
							vac_fncs.mainscan_fns.emplace_back(add);
							vac_fncs.mainscan_ref_fns.emplace_back(function_address);
							//PrintData((PBYTE)mainscan_fnc_add, 8);
						}
						break;
					}
					
				}
				

			
			}

			//std::cout << function_count << " scan(s) found. " << std::endl;


			// ------ this section adds all the addresses of the reference func and the actual mainscan's them selves to a list ------
			for (_MAIN_SCAN add : vac_fncs.mainscan_fns) {
				vac_fncs.sorted_addresses.emplace_back(add.main_scan_address);
			}
			for (PVOID main_scan_ref : vac_fncs.mainscan_ref_fns) {
				vac_fncs.sorted_addresses.emplace_back(main_scan_ref);
			}
			std::sort(vac_fncs.sorted_addresses.begin(), vac_fncs.sorted_addresses.end());

			// ---------------- and then sorts -----------------------------------------------------------------------------

			
			auto next_add = [](PVOID add) -> DWORD { // gets the next address because mainscan function is always followed by the reference func or another mainscan  
				 bool ready = false;
				for (PVOID address : vac_fncs.sorted_addresses) {
				//	std::cout <<"sort add: " <<  address << std::endl;
					if (ready && add != address) return (DWORD)address; // add != address because some module has two ref funcs for the same mainscan
					if (address == add) ready = true;

				}
			};

		
			std::cout << std::setw(20) << std::left <<  dye::light_green("mod name");
			std::cout << std::setw(10) << dye::light_green("count");
			std::cout << std::setw(15) << dye::light_green("address");
			std::cout << std::setw(15) << dye::light_green("ref address");
			std::cout << std::setw(15) << dye::light_green("size") << std::endl;
		
			for (int i = 0; i < main_scan_count; i++) {
				DWORD size = next_add(vac_fncs.mainscan_fns[i].main_scan_address) - DWORD(vac_fncs.mainscan_fns[i].main_scan_address);
				std::cout << std::setw(20) << std::left <<  vac_fncs.mod_name;
				std::cout << std::setw(10)  << vac_fncs.mainscan_fns[i].main_scan_count;
				std::cout << std::setw(15)  << std::hex << vac_fncs.mainscan_fns[i].main_scan_address;
				std::cout << std::setw(15)  << std::hex << vac_fncs.mainscan_ref_fns[i];
				std::cout << std::setw(4) << std::hex << size;
				
			
				UINT64 hash = 0;
				UINT64* fnAddr = (UINT64*)vac_fncs.mainscan_fns[i].main_scan_address;
				for (size_t i = 0; i < size / sizeof(UINT64); i++)
				{
					hash += fnAddr[i];
				}
				if (scanhashMap[hash].empty()) {
					std::cout << dye::yellow("unknown") << std::endl;
				}
				else {
					std::cout << dye::yellow(scanhashMap[hash]) << std::endl;
				}
				
			}
			vac_fncs.mainscan_fns.clear();
			vac_fncs.sorted_addresses.clear();
			vac_fncs.mainscan_ref_fns.clear();

			

			//std::cout << "\n \n";
			VirtualFree(base, file_size, MEM_DECOMMIT | MEM_RELEASE);

		
		//	system("pause");
			
			CloseHandle(file_handle);
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}

	system("pause");
	return 0;
}