
//#include <iostream>
//#include <windows.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>

//
// Boot and Runtime Services
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

//
// Shell Library
//
#include <Library/ShellLib.h>
#include "../UefiDriver/drvproto.h"
typedef unsigned long       DWORD;
typedef unsigned short      WORD;
typedef unsigned char       BYTE;
typedef unsigned __int64 ULONGLONG;
typedef unsigned __int64 size_t;
typedef void *PVOID;
typedef EFI_STATUS(*tfpEfiMain)(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable);

typedef void(*tfpBlpArchSwitchContext)(DWORD type);

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	long   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;

typedef struct _STAGE2_ENTRY_BLOCK {
	EFI_HANDLE ImageHandle;
	EFI_SYSTEM_TABLE* SystemTable;
	tfpBlpArchSwitchContext BlpArchSwitchContext;
	PVOID Stage2Base;
	PVOID PayloadBase;
} STAGE2_ENTRY_BLOCK;



BYTE PayloadBase[] = {0x4D, 0x5A, 0x90};







typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;
typedef ULONG_PTR DWORD_PTR, *PDWORD_PTR;
typedef EFI_STATUS(EFIAPI* print_entry)(PVOID SystemTable, CHAR16* String, ...);
int main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, tfpBlpArchSwitchContext BlpArchSwitchContext, print_entry print, EFI_SYSTEM_TABLE* printSystemTable)
{
	BlpArchSwitchContext(1);

	// Get the boot services from the system table.
	EFI_BOOT_SERVICES* BS = SystemTable->BootServices;

	// Get the memory map.
	UINTN MemoryMapSize = 0;
	EFI_MEMORY_DESCRIPTOR* Buffer = 0;
	UINTN MapKey = 0;
	UINTN DescriptorSize = 0;
	UINT32 DescriptorVersion = 0;
	EFI_STATUS Status = BS->GetMemoryMap(&MemoryMapSize, Buffer, &MapKey, &DescriptorSize, &DescriptorVersion);
	while (Status == EFI_BUFFER_TOO_SMALL) {
		// Add space for some extra entries if needed.
		MemoryMapSize += DescriptorSize * 0x10;
		if (Buffer != NULL) BS->FreePool(Buffer);
		Status = BS->AllocatePool(EfiLoaderData, MemoryMapSize, (VOID**)&Buffer);
		if (EFI_ERROR(Status)) {
			SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Could not allocate memory for EFI memory map\n");

		}
		Status = BS->GetMemoryMap(&MemoryMapSize, Buffer, &MapKey, &DescriptorSize, &DescriptorVersion);
	}

	UINTN CountDescriptors = MemoryMapSize / DescriptorSize;
	UINTN pDescriptor = (UINTN)Buffer;
	UINTN pStack = (UINTN)&MemoryMapSize;

	for (UINTN i = 0; i < CountDescriptors; i++, pDescriptor += DescriptorSize) {
		EFI_MEMORY_DESCRIPTOR* Descriptor = (EFI_MEMORY_DESCRIPTOR*)pDescriptor;
		// All memory allocated by the Windows boot environment is of type EfiLoaderCode.
		if (Descriptor->Type != EfiLoaderCode) continue;
		
		// If this is the current stack, ignore it.
		UINT64 PhysicalEnd = ((Descriptor->NumberOfPages) << 12);
		PhysicalEnd += Descriptor->PhysicalStart;
		if (pStack >= (UINTN)Descriptor->PhysicalStart && pStack < PhysicalEnd) continue;

		// Free this memory.
		BS->FreePages(Descriptor->PhysicalStart, Descriptor->NumberOfPages);
	}

	// Free allocated memory descriptors.
	BS->FreePool(Buffer);

	// Call the entrypoint of the payload.
	PIMAGE_DOS_HEADER Mz = (PIMAGE_DOS_HEADER)PayloadBase;
	PIMAGE_NT_HEADERS Pe = (PIMAGE_NT_HEADERS)((size_t)Mz + Mz->e_lfanew);
	tfpEfiMain EfiMain = (tfpEfiMain)((size_t)Mz + Pe->OptionalHeader.AddressOfEntryPoint);
	EfiMain(ImageHandle, SystemTable);

	while (1);

	// std::cout << "Hello World!\n";
}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
