/* cat.c - command to show the contents of a file  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2005,2007,2008  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <grub/dl.h>
#include <grub/file.h>
#include <grub/disk.h>
#include <grub/term.h>
#include <grub/misc.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <grub/charset.h>
#include <grub/env.h>


#include <grub/mm.h>
#include <grub/partition.h>
#include <grub/msdos_partition.h>
#include <grub/gpt_partition.h>
#include <grub/fs.h>
#include <grub/normal.h>
#include <grub/lua.h>

#include <grub/ventoy.h>
GRUB_MOD_LICENSE ("GPLv3+");

typedef struct {
    grub_uint32_t    magic;
    grub_uint16_t    updateSequenceOffset;
    grub_uint16_t    updateSequenceSize;
    grub_uint64_t    logSequence;
    grub_uint16_t    sequenceNumber;
    grub_uint16_t    hardLinkCount;
    grub_uint16_t    firstAttributeOffset;
    grub_uint16_t    inUse : 1;
    grub_uint16_t    isDirectory : 1;
    grub_uint32_t    usedSize;
    grub_uint32_t    allocatedSize;
    grub_uint64_t    fileReference;
    grub_uint16_t    nextAttributeID;
    grub_uint16_t    unused;
    grub_uint32_t    recordNumber;
} FileRecordHeader;

#pragma pack(push, 1)
typedef struct {
    grub_uint8_t     jump[3];
    grub_uint8_t       name[8];
    grub_uint16_t    bytesPerSector;
    grub_uint8_t     sectorsPerCluster;
    grub_uint16_t    reservedSectors;
    grub_uint8_t     unused0[3];
    grub_uint16_t    unused1;
    grub_uint8_t     media;
    grub_uint16_t    unused2;
    grub_uint16_t    sectorsPerTrack;
    grub_uint16_t    headsPerCylinder;
    grub_uint32_t    hiddenSectors;
    grub_uint32_t    unused3;
    grub_uint32_t    unused4;
    grub_uint64_t    totalSectors;
    grub_uint64_t    mftStart;
    grub_uint64_t    mftMirrorStart;
    grub_uint32_t    clustersPerFileRecord;
    grub_uint32_t    clustersPerIndexBlock;
    grub_uint64_t    serialNumber;
    grub_uint32_t    checksum;
    grub_uint8_t     bootloader[426];
    grub_uint16_t    bootSignature;
} BootSector ; 


typedef struct {
    grub_uint32_t    attributeType;
    grub_uint32_t    length;
    grub_uint8_t     nonResident;
    grub_uint8_t     nameLength;
    grub_uint16_t    nameOffset;
    grub_uint16_t    flags;
    grub_uint16_t    attributeID;
} AttributeHeader;

typedef struct  {
    AttributeHeader header;
    grub_uint32_t    attributeLength;
    grub_uint16_t    attributeOffset;
    grub_uint8_t     indexed;
    grub_uint8_t     unused;
} ResidentAttributeHeader;

typedef struct {
    ResidentAttributeHeader residentHeader;
    grub_uint64_t    parentRecordNumber : 48;
    grub_uint64_t    sequenceNumber : 16;
    grub_uint64_t    creationTime;
    grub_uint64_t    modificationTime;
    grub_uint64_t    metadataModificationTime;
    grub_uint64_t    readTime;
    grub_uint64_t    allocatedSize;
    grub_uint64_t    realSize;
    grub_uint32_t    flags;
    grub_uint32_t    repase;
    grub_uint8_t     fileNameLength;
    grub_uint8_t     namespaceType;
    grub_uint16_t     fileName[1];
} FileNameAttributeHeader;

typedef struct {
    AttributeHeader header;
    grub_uint64_t    firstCluster;
    grub_uint64_t    lastCluster;
    grub_uint16_t    dataRunsOffset;
    grub_uint16_t    compressionUnit;
    grub_uint32_t    unused;
    grub_uint64_t    attributeAllocated;
    grub_uint64_t    attributeSize;
    grub_uint64_t    streamDataSize;
} NonResidentAttributeHeader;

typedef struct {
    grub_uint8_t     lengthFieldBytes : 4;
    grub_uint8_t     offsetFieldBytes : 4;
} RunHeader;

typedef struct {
    grub_uint64_t    parent;
    char* name;
} File;


typedef struct
{
    grub_size_t      length;
    grub_size_t      capacity;
    void* hash_table;
    grub_uint64_t   temp;
} stbds_array_header;

#pragma pack(pop)


static grub_size_t arrlenu(void* arr)
{
    if (arr == NULL)
    {
        return 0;
    }

    stbds_array_header* header = (stbds_array_header*)arr - 1;
    return header->length;
}

#define stbds_header(t)  ((stbds_array_header *) (t) - 1)

#define stbds_arrlen(a)        ((a) ? (grub_uint64_t) stbds_header(a)->length : 0)
#define stbds_arrcap(a)        ((a) ? stbds_header(a)->capacity : 0)
#define STBDS_REALLOC(c,p,s) grub_realloc(p,s)
#ifdef STBDS_STATISTICS
#define STBDS_STATS(x)   x
grub_size_t stbds_array_grow;
grub_size_t stbds_hash_grow;
grub_size_t stbds_hash_shrink;
grub_size_t stbds_hash_rebuild;
grub_size_t stbds_hash_probes;
grub_size_t stbds_hash_alloc;
grub_size_t stbds_rehash_probes;
grub_size_t stbds_rehash_items;
#else
#define STBDS_STATS(x)
#endif


static void* stbds_arrgrowf(void* a, grub_size_t elemsize, grub_size_t addlen, grub_size_t min_cap)
{
    stbds_array_header temp = { 0 }; // force debugging
    void* b;
    grub_size_t min_len = stbds_arrlen(a) + addlen;
    (void)sizeof(temp);

    // compute the minimum capacity needed
    if (min_len > min_cap)
        min_cap = min_len;

    if (min_cap <= stbds_arrcap(a))
        return a;

    // increase needed capacity to guarantee O(1) amortized
    if (min_cap < 2 * stbds_arrcap(a))
        min_cap = 2 * stbds_arrcap(a);
    else if (min_cap < 4)
        min_cap = 4;

    //if (num_prev < 65536) if (a) prev_allocs[num_prev++] = (int *) ((char *) a+1);
    //if (num_prev == 2201)
    //  num_prev = num_prev;
    b = STBDS_REALLOC(NULL, (a) ? stbds_header(a) : 0, elemsize * min_cap + sizeof(stbds_array_header));
    //if (num_prev < 65536) prev_allocs[num_prev++] = (int *) (char *) b;
    b = (char*)b + sizeof(stbds_array_header);
    if (a == NULL) {
        stbds_header(b)->length = 0;
        stbds_header(b)->hash_table = 0;
        stbds_header(b)->temp = 0;
    }
    else {
        STBDS_STATS(++stbds_array_grow);
    }
    stbds_header(b)->capacity = min_cap;

    return b;
}

// Обертка для функции stbds_arrgrowf
static void* stbds_arrgrowf_wrapper(void *a, grub_size_t elemsize, grub_size_t addlen, grub_size_t min_cap) {
    return stbds_arrgrowf(a, elemsize, addlen, min_cap);
}

#define stbds_arrgrow(a,b,c)   ((a) = stbds_arrgrowf_wrapper((a), sizeof *(a), (b), (c)))
#define stbds_arrsetcap(a,n)   (stbds_arrgrow(a,0,n))
#define stbds_arrcap(a)        ((a) ? stbds_header(a)->capacity : 0)
#define stbds_arrsetlen(a,n)   ((stbds_arrcap(a) < (grub_size_t) (n) ? stbds_arrsetcap((a),(grub_size_t)(n)),0 : 0), (a) ? stbds_header(a)->length = (grub_size_t) (n) : 0)
#define arrsetlen   stbds_arrsetlen

#define stbds_arrlen(a)        ((a) ? (grub_uint64_t) stbds_header(a)->length : 0)
#define arrlen      stbds_arrlen

File* files;
grub_file_t drive;
BootSector bootSector;

#define MFT_FILE_SIZE (1024)
grub_uint8_t mftFile[MFT_FILE_SIZE];

#define MFT_FILES_PER_BUFFER (65536)
grub_uint8_t mftBuffer[MFT_FILES_PER_BUFFER * MFT_FILE_SIZE];

static int utf16_to_utf8_length(const grub_uint16_t* utf16, grub_size_t utf16_len) {
    int utf8_len = 0;
    for (grub_size_t i = 0; i < utf16_len; ++i) {
        grub_uint16_t c = utf16[i];
        if (c < 0x80) {
            utf8_len += 1;
        }
        else if (c < 0x800) {
            utf8_len += 2;
        }
        else if (c >= 0xD800 && c <= 0xDFFF) {
            // Surrogate pair
            utf8_len += 4;
            ++i; // Skip the next surrogate pair component
        }
        else {
            utf8_len += 3;
        }
    }
    return utf8_len;
}

static void utf16_to_utf8(const grub_uint16_t* utf16, grub_size_t utf16_len, char* utf8) {
    while (utf16_len--) {
        grub_uint16_t c = *utf16++;
        if (c < 0x80) {
            *utf8++ = (char)c;
        }
        else if (c < 0x800) {
            *utf8++ = 0xC0 | (c >> 6);
            *utf8++ = 0x80 | (c & 0x3F);
        }
        else if (c >= 0xD800 && c <= 0xDFFF) {
            // Surrogate pair
            grub_uint32_t high = c;
            grub_uint32_t low = *utf16++;
            grub_uint32_t codepoint = 0x10000 + (((high & 0x3FF) << 10) | (low & 0x3FF));
            *utf8++ = 0xF0 | (codepoint >> 18);
            *utf8++ = 0x80 | ((codepoint >> 12) & 0x3F);
            *utf8++ = 0x80 | ((codepoint >> 6) & 0x3F);
            *utf8++ = 0x80 | (codepoint & 0x3F);
            utf16_len--; // Skip the next surrogate pair component
        }
        else {
            *utf8++ = 0xE0 | (c >> 12);
            *utf8++ = 0x80 | ((c >> 6) & 0x3F);
            *utf8++ = 0x80 | (c & 0x3F);
        }
    }
    *utf8 = '\0';
}

static char* DuplicateName(grub_uint16_t* name, grub_size_t nameLength) {
    static char* allocationBlock = NULL;
    static grub_size_t bytesRemaining = 0;

    grub_size_t bytesNeeded = utf16_to_utf8_length(name, nameLength) + 1;

    if (bytesRemaining < bytesNeeded) {
        allocationBlock = (char*)grub_malloc((bytesRemaining = 16 * 1024 * 1024));
    }

    char* buffer = allocationBlock;
    buffer[bytesNeeded - 1] = 0;
    utf16_to_utf8(name, nameLength, allocationBlock);

    bytesRemaining -= bytesNeeded;
    allocationBlock += bytesNeeded;

    return buffer;
}


static void Read(void* buffer, grub_uint64_t from, grub_uint64_t count) {
    
    drive->offset = from;
    grub_file_read(drive, buffer, count);
}

static void Write(grub_uint64_t from) {

    drive->offset = from;
    const char *data = "Hello, GRUB!123"; 
    grub_size_t size = grub_strlen(data) + 1;
    grub_disk_write(drive->device->disk, 0, from, size, data);
    grub_file_close(drive);
}

static void PrintFileContent(NonResidentAttributeHeader* dataAttribute) {
    
    RunHeader* dataRun = (RunHeader*)((grub_uint8_t*)dataAttribute + dataAttribute->dataRunsOffset);
    
    grub_uint64_t clusterNumber = 0;
    
    grub_uint64_t bytesPerCluster = bootSector.bytesPerSector * bootSector.sectorsPerCluster;

    while (((grub_uint8_t*)dataRun - (grub_uint8_t*)dataAttribute) < dataAttribute->header.length && dataRun->lengthFieldBytes) {
        
        grub_uint64_t length = 0, offset = 0;

        for (int i = 0; i < dataRun->lengthFieldBytes; i++) {
            length |= (grub_uint64_t)(((grub_uint8_t*)dataRun)[1 + i]) << (i * 8);
        }

        for (int i = 0; i < dataRun->offsetFieldBytes; i++) {
            offset |= (grub_uint64_t)(((grub_uint8_t*)dataRun)[1 + dataRun->lengthFieldBytes + i]) << (i * 8);
        }

        if (offset & ((grub_uint64_t)1 << (dataRun->offsetFieldBytes * 8 - 1))) {
            
            for (int i = dataRun->offsetFieldBytes; i < 8; i++) {
                offset |= (grub_uint64_t)0xFF << (i * 8);
            }
        }

        clusterNumber += offset;
        
        dataRun = (RunHeader*)((grub_uint8_t*)dataRun + 1 + dataRun->lengthFieldBytes + dataRun->offsetFieldBytes);

        //grub_uint8_t* buffer = (grub_uint8_t*)grub_malloc(length * bytesPerCluster);
        
        //Read(buffer, clusterNumber * bytesPerCluster, length * bytesPerCluster);
        
        Write(clusterNumber * bytesPerCluster);
        
        //Read(buffer, clusterNumber * bytesPerCluster, length * bytesPerCluster);
        //for (grub_uint64_t i = 0; i < length * bytesPerCluster; i++) {
        //    grub_printf("%c", (buffer[i])); // тут может быть ошибка 
        //}

        //grub_free(buffer);
    }
}


static char* GetFilePath(grub_uint64_t fileRecordNumber) {
    static char path[1024];
    path[0] = '\0'; // Инициализация пути

    grub_uint64_t visited[1024]; // Для предотвращения зацикливания
    grub_uint64_t visitedCount = 0;
	grub_printf("Found file TEST0: %s \n", files->name);
    while (fileRecordNumber != 0 && fileRecordNumber < arrlen(files)) {
        // Проверка на зацикливание
        for (grub_uint64_t i = 0; i < visitedCount; i++) {
            if (visited[i] == fileRecordNumber) {
                grub_printf("Error: Circular reference detected for record %lu\n", fileRecordNumber);
                return path; // Возврат текущего состояния пути
            }
        }
        if (visitedCount >= 1024) {
            grub_printf("Error: Path recursion limit reached\n");
            return path;
        }
        visited[visitedCount++] = fileRecordNumber;

        // Проверяем, есть ли файл с таким номером
        File* file = &files[fileRecordNumber];
        grub_printf("Found file TEST: %s \n", file->name);
        if (!file || !file->name) {
            grub_printf("Error in parent chain for record %lu\n", fileRecordNumber);
            break;
        }

        // Добавляем имя файла в путь с проверкой длины
        char tempPath[1024];
        grub_snprintf(tempPath, sizeof(tempPath), "/%s", file->name);

        if (grub_strlen(tempPath) + grub_strlen(path) + 1 >= sizeof(path)) {
            grub_printf("Error: Path length exceeds buffer size\n");
            return path;
        }

        // Объединяем новый путь
        grub_snprintf(tempPath, sizeof(tempPath), "/%s%s", file->name, path);
        grub_strncpy(path, tempPath, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0'; // Гарантия нулевого символа

        // Переходим к родительской директории
        fileRecordNumber = file->parent;
    }

    return path;
}

static const struct grub_arg_option options[] =
  {
    {"dos", -1, 0, N_("Accept DOS-style CR/NL line endings."), 0, 0},
    {"set", 's', 0, N_("Store the contents of a file in a variable."), N_("VARNAME"), ARG_TYPE_STRING},
    {0, 0, 0, 0, 0, 0}
  };

static grub_err_t
grub_cmd_cat (grub_extcmd_context_t ctxt, int argc, char **args)
{
	(void)ctxt; // Заглушка для неиспользуемого параметра
    (void)argc;
    (void)args;
    
	drive = grub_file_open("(hd0,gpt3)", GRUB_FILE_TYPE_NONE | GRUB_FILE_TYPE_NO_DECOMPRESS);
	 
	if (!drive)
		return grub_errno;
	grub_off_t in_size = grub_file_size (drive);
	grub_printf("in_size: %lu\n", in_size);
	
	Read(&bootSector, 0, 512);
	
	grub_printf("bootSector");
	grub_uint64_t bytesPerCluster = bootSector.bytesPerSector* bootSector.sectorsPerCluster;

	
	grub_printf("MFT Start: %lu\n", bootSector.mftStart);
	grub_printf("bytesPerCluster: %lu\n", bytesPerCluster);
    
    Read(&mftFile, bootSector.mftStart * bytesPerCluster, MFT_FILE_SIZE);
	
	FileRecordHeader* fileRecord = (FileRecordHeader*)mftFile;
    AttributeHeader* attribute = (AttributeHeader*)(mftFile + fileRecord->firstAttributeOffset);
    NonResidentAttributeHeader* dataAttribute = NULL;
    grub_uint64_t approximateRecordCount = 0;
    if (fileRecord->magic != 0x454C4946) {
		//grub_printf("file size: %s\n", (char*)fileRecord->magic);
        grub_printf("fileRecord->magic\n");
        return -1;
    }
    
    
    while (1) {
        if (attribute->attributeType == 0x80) {
            dataAttribute = (NonResidentAttributeHeader*)attribute;
        }
        else if (attribute->attributeType == 0xB0) {
            approximateRecordCount = ((NonResidentAttributeHeader*)attribute)->attributeSize * 8;
            grub_printf("file size: %llu\n", (unsigned long long)approximateRecordCount);
        }
        else if (attribute->attributeType == 0xFFFFFFFF) {
            break;
        }

        attribute = (AttributeHeader*)((grub_uint8_t*)attribute + attribute->length);
    }

    if (dataAttribute == 0x0) {
        grub_printf("\ndataAttribute\n");
        return -1;
    }
    
    RunHeader* dataRun = (RunHeader*)((grub_uint8_t*)dataAttribute + dataAttribute->dataRunsOffset);
    grub_uint64_t clusterNumber = 0, recordsProcessed = 0;
    
    
    while (((grub_uint8_t*)dataRun - (grub_uint8_t*)dataAttribute) < dataAttribute->header.length && dataRun->lengthFieldBytes) {
        grub_uint64_t length = 0, offset = 0;

        for (int i = 0; i < dataRun->lengthFieldBytes; i++) {
            length |= (grub_uint64_t)(((grub_uint8_t*)dataRun)[1 + i]) << (i * 8);
        }

        for (int i = 0; i < dataRun->offsetFieldBytes; i++) {
            offset |= (grub_uint64_t)(((grub_uint8_t*)dataRun)[1 + dataRun->lengthFieldBytes + i]) << (i * 8);
        }

        if (offset & ((grub_uint64_t)1 << (dataRun->offsetFieldBytes * 8 - 1))) {
            for (int i = dataRun->offsetFieldBytes; i < 8; i++) {
                offset |= (grub_uint64_t)0xFF << (i * 8);
            }
        }

        clusterNumber += offset;
        dataRun = (RunHeader*)((grub_uint8_t*)dataRun + 1 + dataRun->lengthFieldBytes + dataRun->offsetFieldBytes);

        grub_uint64_t filesRemaining = length * bytesPerCluster / MFT_FILE_SIZE;
        grub_uint64_t positionInBlock = 0;

        while (filesRemaining) {
            //fprintf(stderr, "%d%% ", (int)(recordsProcessed * 100 / approximateRecordCount));

            grub_uint64_t filesToLoad = MFT_FILES_PER_BUFFER;
            if (filesRemaining < MFT_FILES_PER_BUFFER) filesToLoad = filesRemaining;
            Read(&mftBuffer, clusterNumber * bytesPerCluster + positionInBlock, filesToLoad * MFT_FILE_SIZE); // вот это придеться переписать  
            positionInBlock += filesToLoad * MFT_FILE_SIZE;
            filesRemaining -= filesToLoad;

            for (grub_uint64_t i = 0; i < filesToLoad; i++) {
                // Even on an SSD, processing the file records takes only a fraction of the time to read the data,
                // so there's not much point in multithreading this.

                 fileRecord = (FileRecordHeader*)(mftBuffer + MFT_FILE_SIZE * i);
                recordsProcessed++;

                if (!fileRecord->inUse) continue;

                attribute = (AttributeHeader*)((grub_uint8_t*)fileRecord + fileRecord->firstAttributeOffset);

                if (fileRecord->magic != 0x454C4946) {
                    grub_printf("\nfileRecord->magic2\n");
                    return -1;
                }

 while ((grub_uint8_t*)attribute - (grub_uint8_t*)fileRecord < MFT_FILE_SIZE) {
                    if (attribute->attributeType == 0x30) {
                        FileNameAttributeHeader* fileNameAttribute = (FileNameAttributeHeader*)attribute;
                        if (fileNameAttribute->namespaceType != 2 && !fileNameAttribute->residentHeader.header.nonResident) {
                            File file = {};
                            file.parent = fileNameAttribute->parentRecordNumber;
                            file.name = DuplicateName(fileNameAttribute->fileName, fileNameAttribute->fileNameLength);

                            grub_uint64_t oldLength = arrlenu(files);
                            //out << file.name << std::endl;

                            if (fileRecord->recordNumber >= oldLength) {
                                arrsetlen(files, fileRecord->recordNumber + 1);
                                grub_memset(files + oldLength, 0, sizeof(File) * (fileRecord->recordNumber - oldLength));
                            }

                            files[fileRecord->recordNumber] = file;
                            
                            if (grub_strcmp(file.name, "test.txt") == 0) {
							 char* filePath = GetFilePath(fileNameAttribute->parentRecordNumber);
                                 if (grub_strcmp(filePath, "/./Users/user/Desktop") == 0) {
										char fullPath[2048]; // Буфер для полного пути
                                        grub_snprintf(fullPath, sizeof(fullPath), "%s/%s", filePath, file.name);
                                        grub_printf("Full Path: %s\n", fullPath);
                                        AttributeHeader* attributeMyFile = (AttributeHeader*)((grub_uint8_t*)attribute + attribute->length);
                                while (1) {
                                    if (attributeMyFile->attributeType == 0x80) {
                                        NonResidentAttributeHeader* attributeMyFileData = (NonResidentAttributeHeader*)attributeMyFile;
                                        PrintFileContent(attributeMyFileData);
                                    }
                                    else if (attributeMyFile->attributeType == 0xFFFFFFFF) {
                                        break;
                                    }
                                    attributeMyFile = (AttributeHeader*)((grub_uint8_t*)attributeMyFile + attributeMyFile->length);
                                }
							}
							}
				          
                        }
                    }
                    else if (attribute->attributeType == 0xFFFFFFFF) {
                        break;
                    }
                    attribute = (AttributeHeader*)((grub_uint8_t*)attribute + attribute->length);
                }
            }
        }
    }
    //grub_file_close(drive);
    grub_printf( "\nFound %ld files.\n", arrlen(files));
  return 0;
}



static grub_extcmd_t cmd;

GRUB_MOD_INIT(cat)
{
  cmd = grub_register_extcmd ("cat", grub_cmd_cat, 0,
			      N_("FILE"), N_("Show the contents of a file."),
			      options);
}

GRUB_MOD_FINI(cat)
{
  grub_unregister_extcmd (cmd);
}
