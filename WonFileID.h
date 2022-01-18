#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _WON_FILE_INFO_BY_HANDLE_CLASS
{
    WonFileBasicInfo = 0,
    WonFileStandardInfo,
    WonFileNameInfo,
    WonFileRenameInfo,
    WonFileDispositionInfo,
    WonFileAllocationInfo,
    WonFileEndOfFileInfo,
    WonFileStreamInfo,
    WonFileCompressionInfo,
    WonFileAttributeTagInfo,
    WonFileIdBothDirectoryInfo,
    WonFileIdBothDirectoryRestartInfo,
    WonFileIoPriorityHintInfo,
    WonFileRemoteProtocolInfo,
    WonFileFullDirectoryInfo,
    WonFileFullDirectoryRestartInfo,
    WonFileStorageInfo,
    WonFileAlignmentInfo,
    WonFileIdInfo,
    WonFileIdExtdDirectoryInfo,
    WonFileIdExtdDirectoryRestartInfo,
    WonMaximumFileInfoByHandleClass
} WON_FILE_INFO_BY_HANDLE_CLASS, *PWON_FILE_INFO_BY_HANDLE_CLASS;

typedef struct _WON_FILE_ID_128
{
    ULONGLONG LowPart;
    ULONGLONG HighPart;
} WON_FILE_ID_128, *PWON_FILE_ID_128;

typedef enum _WON_FILE_ID_TYPE
{
    WonFileIdType,
    WonObjectIdType,
    WonExtendedFileIdType,
    WonMaximumFileIdType
} WON_FILE_ID_TYPE, *PWON_FILE_ID_TYPE;

typedef struct _WON_FILE_ID_DESCRIPTOR
{
    DWORD dwSize;
    WON_FILE_ID_TYPE Type;
    union
    {
        LARGE_INTEGER FileId;
        GUID ObjectId;
        WON_FILE_ID_128 ExtendedFileId;
    };
} WON_FILE_ID_DESCRIPTOR, *LPWON_FILE_ID_DESCRIPTOR;

BOOL
WINAPI
WonSetFileInformationByHandle(
    HANDLE hFile,
    WON_FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    LPVOID lpFileInformation,
    DWORD dwBufferSize);

BOOL
WINAPI
WonGetFileInformationByHandleEx(
    HANDLE hFile,
    WON_FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    LPVOID lpFileInformation,
    DWORD dwBufferSize);

HANDLE
WINAPI
WonOpenFileById(
    HANDLE hVolumeHint,
    LPWON_FILE_ID_DESCRIPTOR lpFileId,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwFlagsAndAttributes);

#if defined(_WONVER) && (_WONVER < 0x0600)
    #define SetFileInformationByHandle WonSetFileInformationByHandle
    #define GetFileInformationByHandleEx WonGetFileInformationByHandleEx
    #define OpenFileById WonOpenFileById
    #define FILE_INFO_BY_HANDLE_CLASS WON_FILE_INFO_BY_HANDLE_CLASS
    #define PFILE_INFO_BY_HANDLE_CLASS PWON_FILE_INFO_BY_HANDLE_CLASS
    #define FILE_ID_128 WON_FILE_ID_128
    #define PFILE_ID_128 PWON_FILE_ID_128
    #define FileIdType WonFileIdType
    #define ObjectIdType WonObjectIdType
    #define ExtendedFileIdType WonExtendedFileIdType
    #define MaximumFileIdType WonMaximumFileIdType
    #define FILE_ID_TYPE WON_FILE_ID_TYPE
    #define PFILE_ID_TYPE PWON_FILE_ID_TYPE
    #define FILE_ID_DESCRIPTOR WON_FILE_ID_DESCRIPTOR
    #define LPFILE_ID_DESCRIPTOR LPWON_FILE_ID_DESCRIPTOR
#endif

#ifdef __cplusplus
}
#endif
