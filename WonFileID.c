#include <windows.h>
#include <winternl.h>
#include "WonFileID.h"

typedef enum _WON_PRIORITY_HINT
{
    WonIoPriorityHintVeryLow = 0,
    WonIoPriorityHintLow,
    WonIoPriorityHintNormal,
    WonMaximumIoPriorityHintType
} WON_PRIORITY_HINT;

typedef struct _WON_FILE_BASIC_INFO
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} WON_FILE_BASIC_INFO, *PWON_FILE_BASIC_INFO;

typedef struct _WON_FILE_STANDARD_INFO
{
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} WON_FILE_STANDARD_INFO, *PWON_FILE_STANDARD_INFO;

typedef struct _WON_FILE_NAME_INFO
{
    ULONG FileNameLength;
    WCHAR FileName[1];
} WON_FILE_NAME_INFO, *PWON_FILE_NAME_INFO;

typedef struct _WON_FILE_RENAME_INFO
{
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} WON_FILE_RENAME_INFO, *PWON_FILE_RENAME_INFO;

typedef struct _WON_FILE_DISPOSITION_INFO
{
    BOOLEAN DeleteFile;
} WON_FILE_DISPOSITION_INFO, *PWON_FILE_DISPOSITION_INFO;

typedef struct _WON_FILE_STREAM_INFO
{
    ULONG NextEntryOffset;
    ULONG StreamNameLength;
    LARGE_INTEGER StreamSize;
    LARGE_INTEGER StreamAllocationSize;
    WCHAR StreamName[1];
} WON_FILE_STREAM_INFO, *PWON_FILE_STREAM_INFO;

typedef struct _WON_FILE_ID_BOTH_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} WON_FILE_ID_BOTH_DIR_INFORMATION, *PWON_FILE_ID_BOTH_DIR_INFORMATION;

typedef struct _WON_FILE_ALLOCATION_INFO
{
    LARGE_INTEGER AllocationSize;
} WON_FILE_ALLOCATION_INFO, *PWON_FILE_ALLOCATION_INFO;

typedef struct _WON_FILE_END_OF_FILE_INFO
{
    LARGE_INTEGER EndOfFile;
} WON_FILE_END_OF_FILE_INFO, *PWON_FILE_END_OF_FILE_INFO;

typedef enum _WON_FILE_INFORMATION_CLASS
{
    WonFileDirectoryInformation = 1,
    WonFileFullDirectoryInformation,
    WonFileBothDirectoryInformation,
    WonFileBasicInformation,
    WonFileStandardInformation,
    WonFileInternalInformation,
    WonFileEaInformation,
    WonFileAccessInformation,
    WonFileNameInformation,
    WonFileRenameInformation,
    WonFileLinkInformation,
    WonFileNamesInformation,
    WonFileDispositionInformation,
    WonFilePositionInformation,
    WonFileFullEaInformation,
    WonFileModeInformation,
    WonFileAlignmentInformation,
    WonFileAllInformation,
    WonFileAllocationInformation,
    WonFileEndOfFileInformation,
    WonFileAlternateNameInformation,
    WonFileStreamInformation,
    WonFilePipeInformation,
    WonFilePipeLocalInformation,
    WonFilePipeRemoteInformation,
    WonFileMailslotQueryInformation,
    WonFileMailslotSetInformation,
    WonFileCompressionInformation,
    WonFileObjectIdInformation,
    WonFileCompletionInformation,
    WonFileMoveClusterInformation,
    WonFileQuotaInformation,
    WonFileReparsePointInformation,
    WonFileNetworkOpenInformation,
    WonFileAttributeTagInformation,
    WonFileTrackingInformation,
    WonFileIdBothDirectoryInformation,
    WonFileIdFullDirectoryInformation,
    WonFileValidDataLengthInformation,
    WonFileShortNameInformation,
    WonFileIoCompletionNotificationInformation,
    WonFileIoStatusBlockRangeInformation,
    WonFileIoPriorityHintInformation,
    WonFileSfioReserveInformation,
    WonFileSfioVolumeInformation,
    WonFileHardLinkInformation,
    WonFileProcessIdsUsingFileInformation,
    WonFileNormalizedNameInformation,
    WonFileNetworkPhysicalNameInformation,
    WonFileIdGlobalTxDirectoryInformation,
    WonFileIsRemoteDeviceInformation,
    WonFileAttributeCacheInformation,
    WonFileNumaNodeInformation,
    WonFileStandardLinkInformation,
    WonFileRemoteProtocolInformation,
    WonFileMaximumInformation
} WON_FILE_INFORMATION_CLASS, *PWON_FILE_INFORMATION_CLASS;

typedef struct _WON_FILE_COMPRESSION_INFORMATION
{
    LARGE_INTEGER CompressedFileSize;
    USHORT CompressionFormat;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved[3];
} WON_FILE_COMPRESSION_INFORMATION, *PWON_FILE_COMPRESSION_INFORMATION;

typedef struct _WON_FILE_ATTRIBUTE_TAG_INFORMATION
{
    ULONG FileAttributes;
    ULONG ReparseTag;
} WON_FILE_ATTRIBUTE_TAG_INFORMATION, *PWON_FILE_ATTRIBUTE_TAG_INFORMATION;

typedef enum _WON_IO_PRIORITY_HINT
{
    WonIoPriorityVeryLow = 0,
    WonIoPriorityLow,
    WonIoPriorityNormal,
    WonIoPriorityHigh,
    WonIoPriorityCritical,
    WonMaxIoPriorityTypes
} WON_IO_PRIORITY_HINT;

typedef struct _WON_FILE_IO_PRIORITY_HINT_INFO
{
    WON_IO_PRIORITY_HINT PriorityHint;
} WON_FILE_IO_PRIORITY_HINT_INFO, *PWON_FILE_IO_PRIORITY_HINT_INFO;

typedef ULONG (APIENTRY* FN_NtRtlStatusToDosError)(NTSTATUS);
typedef NTSTATUS (APIENTRY *FN_NtSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                                     FILE_INFORMATION_CLASS);
typedef NTSTATUS (APIENTRY *FN_NtQueryDirectoryFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                                     PIO_STATUS_BLOCK, PVOID, ULONG,
                                                     FILE_INFORMATION_CLASS, BOOLEAN,
                                                     PUNICODE_STRING, BOOLEAN);
typedef NTSTATUS (APIENTRY *FN_NtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                                       FILE_INFORMATION_CLASS);
typedef NTSTATUS (APIENTRY *FN_NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                             PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
                                             ULONG, ULONG, PVOID, ULONG);

static FN_NtRtlStatusToDosError s_pRtlStatusToDosError = NULL;
static FN_NtSetInformationFile s_pNtSetInformationFile = NULL;
static FN_NtQueryDirectoryFile s_pNtQueryDirectoryFile = NULL;
static FN_NtQueryInformationFile s_pNtQueryInformationFile = NULL;
static FN_NtCreateFile s_pNtCreateFile = NULL;

static DWORD APIENTRY StatusToDosError(NTSTATUS Status)
{
    if (!s_pRtlStatusToDosError)
        s_pRtlStatusToDosError = (FN_NtRtlStatusToDosError)
            GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "RtlNtStatusToDosError");
    return (*s_pRtlStatusToDosError)(Status);
}

static VOID APIENTRY SetNtStatus(NTSTATUS Status)
{
    DWORD dwError = StatusToDosError(Status);
    SetLastError(dwError);
}

static NTSTATUS APIENTRY
SetInformationFile(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass)
{
    if (!s_pNtSetInformationFile)
        s_pNtSetInformationFile = (FN_NtSetInformationFile)
            GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtSetInformationFile");
    return (*s_pNtSetInformationFile)(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

static NTSTATUS APIENTRY
QueryInformationFile(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass)
{
    if (!s_pNtQueryInformationFile)
        s_pNtQueryInformationFile = (FN_NtQueryInformationFile)
            GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtQueryInformationFile");
    return (*s_pNtQueryInformationFile)(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

BOOL WINAPI
WonSetFileInformationByHandle(
    HANDLE                        hFile,
    WON_FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    LPVOID                        lpFileInformation,
    DWORD                         dwBufferSize)
{
    WON_FILE_INFORMATION_CLASS InfoClass;
    DWORD dwLength;
    PWON_FILE_IO_PRIORITY_HINT_INFO pHintInfo;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS status;

    switch (FileInformationClass)
    {
    case WonFileBasicInformation:
        InfoClass = WonFileBasicInformation;
        dwLength = sizeof(WON_FILE_BASIC_INFO);
        break;

    case WonFileStandardInformation:
        InfoClass = WonFileStandardInformation;
        dwLength = sizeof(WON_FILE_STANDARD_INFO);
        break;

    case WonFileRenameInformation:
        InfoClass = WonFileRenameInformation;
        dwLength = sizeof(WON_FILE_RENAME_INFO);
        break;

    case WonFileDispositionInformation:
        InfoClass = WonFileDispositionInformation;
        dwLength = sizeof(WON_FILE_DISPOSITION_INFO);
        break;

    case WonFileAllocationInformation:
        InfoClass = WonFileAllocationInformation;
        dwLength = sizeof(WON_FILE_ALLOCATION_INFO);
        break;

    case WonFileEndOfFileInformation:
        InfoClass = WonFileEndOfFileInformation;
        dwLength = sizeof(WON_FILE_END_OF_FILE_INFO);
        break;

    case WonFileIoPriorityHintInformation:
        InfoClass = WonFileIoPriorityHintInformation;
        dwLength = sizeof(WON_FILE_IO_PRIORITY_HINT_INFO);
        pHintInfo = (PWON_FILE_IO_PRIORITY_HINT_INFO)lpFileInformation;
        if (pHintInfo->PriorityHint >= WonMaximumIoPriorityHintType)
            goto Quit;
        break;

    default: Quit:
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (dwLength > dwBufferSize)
    {
        SetLastError(ERROR_BAD_LENGTH);
        return 0;
    }

    status = SetInformationFile(hFile, &IoStatusBlock, lpFileInformation, dwBufferSize, InfoClass);
    if (!NT_SUCCESS(status))
    {
        SetNtStatus(status);
        return FALSE;
    }

    return TRUE;
}

BOOL WINAPI
WonGetFileInformationByHandleEx(
    HANDLE                          hFile,
    WON_FILE_INFO_BY_HANDLE_CLASS   FileInformationClass,
    LPVOID                          lpFileInformation,
    DWORD                           dwBufferSize)
{
    IO_STATUS_BLOCK io;
    FILE_INFORMATION_CLASS InfoClass;
    DWORD dwLength;
    BOOL bIsDir = FALSE;
    BOOLEAN bRestartScan = FALSE; // ebp-0x4
    NTSTATUS status;

    switch (FileInformationClass)
    {
    case WonFileAttributeTagInfo:
        InfoClass = WonFileAttributeTagInformation;
        dwLength = sizeof(WON_FILE_ATTRIBUTE_TAG_INFORMATION);
        break;

    case WonFileIdBothDirectoryInfo:
        InfoClass = WonFileIdBothDirectoryInformation;
        bIsDir = TRUE;
        dwLength = sizeof(WON_FILE_ID_BOTH_DIR_INFORMATION);
        bRestartScan = FALSE;
        break;

    case WonFileIdBothDirectoryRestartInfo:
        InfoClass = WonFileIdBothDirectoryInformation;
        bIsDir = TRUE;
        dwLength = sizeof(WON_FILE_ID_BOTH_DIR_INFORMATION);
        bRestartScan = TRUE;
        break;

    case WonFileCompressionInfo:
        InfoClass = WonFileCompressionInformation;
        dwLength = sizeof(WON_FILE_COMPRESSION_INFORMATION);
        break;

    case WonFileBasicInfo:
        InfoClass = WonFileBasicInformation;
        dwLength = sizeof(WON_FILE_BASIC_INFO);
        break;

    case WonFileStandardInfo:
        InfoClass = WonFileStandardInformation;
        dwLength = sizeof(WON_FILE_STANDARD_INFO);
        break;

    case WonFileNameInfo:
        InfoClass = WonFileNameInformation;
        dwLength = sizeof(WON_FILE_NAME_INFO);
        break;

    case WonFileStreamInfo:
        InfoClass = WonFileStreamInformation;
        dwLength = sizeof(WON_FILE_STREAM_INFO);
        break;

    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (dwLength > dwBufferSize)
    {
        SetLastError(ERROR_BAD_LENGTH);
        return FALSE;
    }

    if (bIsDir)
    {
        if (!s_pNtQueryDirectoryFile)
            s_pNtQueryDirectoryFile = (FN_NtQueryDirectoryFile)
                GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtQueryDirectoryFile");
        status = (*s_pNtQueryDirectoryFile)(hFile, NULL, NULL, NULL, &io, lpFileInformation,
                                            dwBufferSize, InfoClass, FALSE, NULL, bRestartScan);
    }
    else
    {
        status = QueryInformationFile(hFile, &io, lpFileInformation, dwBufferSize, InfoClass);
    }

    if (!NT_SUCCESS(status))
    {
        SetNtStatus(status);
        return FALSE;
    }

    if (FileInformationClass == WonFileStreamInfo && io.Information == FILE_SUPERSEDED)
    {
#ifndef STATUS_END_OF_FILE
    #define STATUS_END_OF_FILE ((NTSTATUS)0xC0000011)
#endif
        SetNtStatus(STATUS_END_OF_FILE);
        return FALSE;
    }

    return TRUE;
}

HANDLE WINAPI
WonOpenFileById(
    HANDLE hVolumeHint,
    LPWON_FILE_ID_DESCRIPTOR lpFileId,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwFlagsAndAttributes)
{
    OBJECT_ATTRIBUTES ObjAttrs;
    UNICODE_STRING ObjectName;
    DWORD dwCreateOptions;
    HANDLE hFile;
    IO_STATUS_BLOCK io;
    NTSTATUS status;

    if (!lpFileId)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    if (lpFileId->dwSize < sizeof(WON_FILE_ID_DESCRIPTOR))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    switch (lpFileId->Type)
    {
    case WonFileIdType:
        ObjectName.Length = sizeof(LARGE_INTEGER);
        ObjectName.MaximumLength = sizeof(LARGE_INTEGER);
        ObjectName.Buffer = (PWSTR)&lpFileId->FileId;
        break;

    case WonObjectIdType:
        ObjectName.Length = sizeof(WON_FILE_ID_128);
        ObjectName.MaximumLength = sizeof(WON_FILE_ID_128);
        ObjectName.Buffer = (PWSTR)&lpFileId->ExtendedFileId;
        break;

    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    ZeroMemory(&ObjAttrs, sizeof(ObjAttrs));
    ObjAttrs.Length = sizeof(ObjAttrs);
    ObjAttrs.RootDirectory = hVolumeHint;
    ObjAttrs.ObjectName = &ObjectName;
    ObjAttrs.Attributes = OBJ_CASE_INSENSITIVE;

#ifndef FILE_ATTRIBUTE_VALID_FLAGS
    #define FILE_ATTRIBUTE_VALID_FLAGS 0x00007fb7
#endif
    dwCreateOptions = (dwFlagsAndAttributes & FILE_ATTRIBUTE_VALID_FLAGS);

    if (dwFlagsAndAttributes & FILE_ATTRIBUTE_DIRECTORY)
        dwCreateOptions |= FILE_DIRECTORY_FILE;
    else
        dwCreateOptions |= FILE_NON_DIRECTORY_FILE;

    if (dwFlagsAndAttributes & FILE_FLAG_WRITE_THROUGH)
        dwCreateOptions |= FILE_WRITE_THROUGH;

    if (dwFlagsAndAttributes & FILE_FLAG_SEQUENTIAL_SCAN)
        dwCreateOptions |= FILE_SEQUENTIAL_ONLY;

    if (dwFlagsAndAttributes & FILE_FLAG_RANDOM_ACCESS)
        dwCreateOptions |= FILE_RANDOM_ACCESS;

    if (dwFlagsAndAttributes & FILE_FLAG_BACKUP_SEMANTICS)
        dwCreateOptions |= FILE_OPEN_FOR_BACKUP_INTENT;

    if (dwFlagsAndAttributes & FILE_FLAG_NO_BUFFERING)
        dwCreateOptions |= FILE_NO_INTERMEDIATE_BUFFERING;

    if (dwFlagsAndAttributes & FILE_FLAG_OPEN_REPARSE_POINT)
        dwCreateOptions |= FILE_OPEN_REPARSE_POINT;

    if (dwFlagsAndAttributes & FILE_FLAG_OPEN_NO_RECALL)
        dwCreateOptions |= FILE_OPEN_NO_RECALL;

    if (dwFlagsAndAttributes & FILE_FLAG_DELETE_ON_CLOSE)
    {
        dwCreateOptions |= FILE_DELETE_ON_CLOSE;
        dwDesiredAccess |= DELETE;
    }

    dwDesiredAccess |= SYNCHRONIZE | FILE_READ_ATTRIBUTES;
    dwCreateOptions |= FILE_OPEN_BY_FILE_ID;

    if (!s_pNtCreateFile)
        s_pNtCreateFile = (FN_NtCreateFile)
            GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtCreateFile");

    status = (*s_pNtCreateFile)(&hFile, (ACCESS_MASK)dwDesiredAccess, &ObjAttrs, &io, NULL, 0, dwShareMode,
                                FILE_OPEN_IF, dwCreateOptions, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        hFile = INVALID_HANDLE_VALUE;
        SetNtStatus(status);
    }

    return hFile;
}
