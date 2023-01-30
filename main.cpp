#include <iostream>
#include <windows.h>
#include "md5.h"
#include "utility.h"

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

int main() {

    WIN32_FIND_DATA fd;
    std::string path = "C:\\Users\\admin\\Desktop\\csgo shit\\moduledump\\good dump\\modules\\";
    HANDLE hFind = FindFirstFile(std::string(path + "*.dll").c_str(), &fd);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            
            
            std::cout << fd.cFileName << std::endl;
            std::string str_file_name(fd.cFileName);
            std::cout << path + str_file_name << std::endl;
        
            HANDLE file_handle =
                CreateFileA(std::string(path + str_file_name).c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL);


            if (file_handle) {
                DWORD file_size = GetFileSize(file_handle, NULL);
                PVOID base = VirtualAlloc(NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            //    std::cout << file_size << std::endl;
                if (ReadFile(file_handle, base, file_size, NULL, NULL)) {

                    DWORD text_add = get_section_address(base, ".text");
                    
                    if (text_add) {

                        std::cout << ".text add: " << std::hex << text_add << std::endl;
                        PDWORD function_list = (PDWORD)((DWORD)base + text_add + 0x4);

                        if (!function_list) {
                            std::cout << "failed to get function list " << std::endl;
                        }
                        else {
                            std::cout << "function list add: " << function_list << std::endl;
                            for (int i = 0;i < 100000000; i++) {
                                PBYTE function_address = (PBYTE)(function_list[i]);

                                if (function_address) {
                                    //std::cout << "function address: " << std::hex << DWORD((PBYTE)function_address) << std::endl;
                                    function_address = (PBYTE)resolve_relative_address(base, (DWORD)function_address);
                                   // PrintData(function_address, 20);
                                  
                                    PVOID scan_add{};

                                    if (function_address) {

                                        for (function_address;; function_address += sizeof(byte)) {

                                            BYTE curr_byte = *(BYTE*)(function_address);

                                            if (curr_byte == 0xC7) { // 0xc7 is byte for return address 

                                                function_address -= 5;

                                                scan_add = *(PVOID*)(function_address + 1);

                                                scan_add = (PVOID)resolve_relative_address(base, (DWORD)(scan_add));
                                                
                                             

                                                if (scan_add) {
                                                    std::cout << "scan_add found " << std::hex << (DWORD)scan_add << std::endl;
                                                    PVOID mainscan_fnc_add = *(PVOID*)((DWORD)scan_add + 0xC);
                                                    mainscan_fnc_add = (PVOID)resolve_relative_address(base, (DWORD)mainscan_fnc_add);
                                                    PrintData((PBYTE)mainscan_fnc_add, 40);
                                                }
                                                break;
                                            }
                                        }

                                    }
                                    else {
                                        std::cout << "failed to resolve function address" << std::endl;
                                        break;
                                    }
                                }
                                else {
                                    system("pause");
                                    std::cout << "failed to get function address" << std::endl;
                                    break;
                                }
                                //   std::cout << &function_address << std::endl;
                               

                                if (GetAsyncKeyState(VK_END)) {
                                    Sleep(150);
                                    break;
                                }
                            }
                        }                    
                    }
                    else {
                        std::cout << "failed to get text section address" << std::endl;
                    }                            
                }
                else {
                    std::cout << "error reading file "  << std::hex << GetLastError() <<  std::endl;
                }
                VirtualFree(base, file_size, MEM_DECOMMIT | MEM_RELEASE);
            }
            else {
                std::cout << "error getting file handle " <<  std::hex << GetLastError() <<  std::endl;
            }
            system("pause");
            system("cls");
           
            CloseHandle(file_handle);
        } while (FindNextFile(hFind, &fd));
        FindClose(hFind);
    }

      system("pause");
    return 0;
}