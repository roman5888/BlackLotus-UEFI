

#define VOID  void
#define EFIAPI				__cdecl
typedef unsigned int        UINT32, * PUINT32;
typedef unsigned __int64    UINT64, * PUINT64;
typedef UINT64 EFI_PHYSICAL_ADDRESS;
typedef UINT64 EFI_VIRTUAL_ADDRESS;
typedef unsigned short CHAR16;
typedef VOID* EFI_HANDLE;
typedef VOID* EFI_EVENT;
typedef signed int          INT32, * PINT32;
typedef unsigned char       BYTE;
typedef BYTE  BOOLEAN;

typedef VOID* EFI_HANDLE;

typedef struct {
	///
	/// Type of the memory region.
	/// Type EFI_MEMORY_TYPE is defined in the
	/// AllocatePages() function description.
	///
	UINT32                  Type;
	///
	/// Physical address of the first byte in the memory region. PhysicalStart must be
	/// aligned on a 4 KiB boundary, and must not be above 0xfffffffffffff000. Type
	/// EFI_PHYSICAL_ADDRESS is defined in the AllocatePages() function description
	///
	EFI_PHYSICAL_ADDRESS    PhysicalStart;
	///
	/// Virtual address of the first byte in the memory region.
	/// VirtualStart must be aligned on a 4 KiB boundary,
	/// and must not be above 0xfffffffffffff000.
	///
	EFI_VIRTUAL_ADDRESS     VirtualStart;
	///
	/// NumberOfPagesNumber of 4 KiB pages in the memory region.
	/// NumberOfPages must not be 0, and must not be any value
	/// that would represent a memory page with a start address,
	/// either physical or virtual, above 0xfffffffffffff000.
	///
	UINT64                  NumberOfPages;
	///
	/// Attributes of the memory region that describe the bit mask of capabilities
	/// for that memory region, and not necessarily the current settings for that
	/// memory region.
	///
	UINT64                  Attribute;
} EFI_MEMORY_DESCRIPTOR;


typedef struct {
	///
	/// A 64-bit signature that identifies the type of table that follows.
	/// Unique signatures have been generated for the EFI System Table,
	/// the EFI Boot Services Table, and the EFI Runtime Services Table.
	///
	UINT64    Signature;
	///
	/// The revision of the EFI Specification to which this table
	/// conforms. The upper 16 bits of this field contain the major
	/// revision value, and the lower 16 bits contain the minor revision
	/// value. The minor revision values are limited to the range of 00..99.
	///
	UINT32    Revision;
	///
	/// The size, in bytes, of the entire table including the EFI_TABLE_HEADER.
	///
	UINT32    HeaderSize;
	///
	/// The 32-bit CRC for the entire table. This value is computed by
	/// setting this field to 0, and computing the 32-bit CRC for HeaderSize bytes.
	///
	UINT32    CRC32;
	///
	/// Reserved field that must be set to 0.
	///
	UINT32    Reserved;
} EFI_TABLE_HEADER;

typedef enum {
	///
	/// Not used.
	///
	EfiReservedMemoryType,
	///
	/// The code portions of a loaded application.
	/// (Note that UEFI OS loaders are UEFI applications.)
	///
	EfiLoaderCode,
	///
	/// The data portions of a loaded application and the default data allocation
	/// type used by an application to allocate pool memory.
	///
	EfiLoaderData,
	///
	/// The code portions of a loaded Boot Services Driver.
	///
	EfiBootServicesCode,
	///
	/// The data portions of a loaded Boot Serves Driver, and the default data
	/// allocation type used by a Boot Services Driver to allocate pool memory.
	///
	EfiBootServicesData,
	///
	/// The code portions of a loaded Runtime Services Driver.
	///
	EfiRuntimeServicesCode,
	///
	/// The data portions of a loaded Runtime Services Driver and the default
	/// data allocation type used by a Runtime Services Driver to allocate pool memory.
	///
	EfiRuntimeServicesData,
	///
	/// Free (unallocated) memory.
	///
	EfiConventionalMemory,
	///
	/// Memory in which errors have been detected.
	///
	EfiUnusableMemory,
	///
	/// Memory that holds the ACPI tables.
	///
	EfiACPIReclaimMemory,
	///
	/// Address space reserved for use by the firmware.
	///
	EfiACPIMemoryNVS,
	///
	/// Used by system firmware to request that a memory-mapped IO region
	/// be mapped by the OS to a virtual address so it can be accessed by EFI runtime services.
	///
	EfiMemoryMappedIO,
	///
	/// System memory-mapped IO region that is used to translate memory
	/// cycles to IO cycles by the processor.
	///
	EfiMemoryMappedIOPortSpace,
	///
	/// Address space reserved by the firmware for code that is part of the processor.
	///
	EfiPalCode,
	///
	/// A memory region that operates as EfiConventionalMemory,
	/// however it happens to also support byte-addressable non-volatility.
	///
	EfiPersistentMemory,
	///
	/// A memory region that describes system memory that has not been accepted
	/// by a corresponding call to the underlying isolation architecture.
	///
	EfiUnacceptedMemoryType,
	EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef EFI_STATUS(EFIAPI* EFI_GET_MEMORY_MAP) (
	UINT64* MemoryMapSize,
	EFI_MEMORY_DESCRIPTOR* MemoryMap,
	UINT64* MapKey,
	UINT64* DescriptorSize,
	UINT32* DescriptorVersion
	);


typedef EFI_STATUS(EFIAPI* EFI_FREE_POOL)(
	VOID* Buffer
	);

typedef EFI_STATUS(EFIAPI* EFI_ALLOCATE_POOL)(
	EFI_MEMORY_TYPE              PoolType,
	UINT64                        Size,
	VOID** Buffer
	);

typedef EFI_STATUS(EFIAPI* EFI_FREE_PAGES)(
	EFI_PHYSICAL_ADDRESS         Memory,
	  UINT64                        Pages
	);
typedef struct {
	///
	/// The table header for the EFI Boot Services Table.
	///
	EFI_TABLE_HEADER                              Hdr;

	//
	// Task Priority Services
	//
	UINT64                                 RaiseTPL;
	UINT64                               RestoreTPL;

	//
	// Memory Services
	//
	UINT64                            AllocatePages;
	EFI_FREE_PAGES                                FreePages;
	EFI_GET_MEMORY_MAP                            GetMemoryMap;
	EFI_ALLOCATE_POOL                             AllocatePool;
	EFI_FREE_POOL                                 FreePool;

	//
	// Event & Timer Services
	//
	UINT64                              CreateEvent2;
	UINT64                                 SetTimer;
	UINT64                            WaitForEvent;
	UINT64                              SignalEvent;
	UINT64                               CloseEvent;
	UINT64                               CheckEvent;

	//
	// Protocol Handler Services
	//
	UINT64                InstallProtocolInterface;
	UINT64              ReinstallProtocolInterface;
	UINT64              UninstallProtocolInterface;
	UINT64                          HandleProtocol;
	VOID* Reserved;
	UINT64                  RegisterProtocolNotify;
	UINT64                             LocateHandle;
	UINT64                        LocateDevicePath;
	UINT64               InstallConfigurationTable;

	//
	// Image Services
	//
	UINT64                                LoadImage2;
	UINT64                               StartImage;
	UINT64                                      Exit;
	UINT64                              UnloadImage;
	UINT64                        ExitBootServices;

	//
	// Miscellaneous Services
	//
	UINT64                  GetNextMonotonicCount;
	UINT64                                     Stall;
	UINT64                        SetWatchdogTimer;

	//
	// DriverSupport Services
	//
	UINT64                        ConnectController;
	UINT64                     DisconnectController;

	//
	// Open and Close Protocol Services
	//
	UINT64                             OpenProtocol;
	UINT64                            CloseProtocol;
	UINT64                 OpenProtocolInformation;

	//
	// Library Services
	//
	UINT64                     ProtocolsPerHandle;
	UINT64                      LocateHandleBuffer;
	UINT64                           LocateProtocol;
	UINT64      InstallMultipleProtocolInterfaces;
	UINT64    UninstallMultipleProtocolInterfaces;

	//
	// 32-bit CRC Services
	//
	UINT64                           CalculateCrc32;

	//
	// Miscellaneous Services
	//
	UINT64                                  CopyMem;
	UINT64                                   SetMem;
	UINT64                           CreateEventEx2;
} EFI_BOOT_SERVICES;


typedef struct {
	///
	/// The table header for the EFI System Table.
	///
	EFI_TABLE_HEADER                   Hdr;
	///
	/// A pointer to a null terminated string that identifies the vendor
	/// that produces the system firmware for the platform.
	///
	CHAR16* FirmwareVendor;
	///
	/// A firmware vendor specific value that identifies the revision
	/// of the system firmware for the platform.
	///
	UINT32                             FirmwareRevision;
	///
	/// The handle for the active console input device. This handle must support
	/// EFI_SIMPLE_TEXT_INPUT_PROTOCOL and EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL.
	///
	EFI_HANDLE                         ConsoleInHandle;
	///
	/// A pointer to the EFI_SIMPLE_TEXT_INPUT_PROTOCOL interface that is
	/// associated with ConsoleInHandle.
	///
	UINT64* ConIn;
	///
	/// The handle for the active console output device.
	///
	EFI_HANDLE                         ConsoleOutHandle;
	///
	/// A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL interface
	/// that is associated with ConsoleOutHandle.
	///
	UINT64* ConOut;
	///
	/// The handle for the active standard error console device.
	/// This handle must support the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.
	///
	EFI_HANDLE                         StandardErrorHandle;
	///
	/// A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL interface
	/// that is associated with StandardErrorHandle.
	///
	UINT64* StdErr;
	///
	/// A pointer to the EFI Runtime Services Table.
	///
	UINT64* RuntimeServices;
	///
	/// A pointer to the EFI Boot Services Table.
	///
	EFI_BOOT_SERVICES* BootServices;
	///
	/// The number of system configuration tables in the buffer ConfigurationTable.
	///
	UINT64                              NumberOfTableEntries;
	///
	/// A pointer to the system configuration tables.
	/// The number of entries in the table is NumberOfTableEntries.
	///
	UINT64* ConfigurationTable;
} EFI_SYSTEM_TABLE;
