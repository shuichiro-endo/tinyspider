/*
 * Title:  stdfunc.h
 * Author: Shuichiro Endo
 */

/*
 * Reference:
 * https://www.vergiliusproject.com/kernels/x64/windows-11/25h2
 * https://ntdoc.m417z.com/
 * https://j00ru.vexillium.org/syscalls/nt/64/
 * https://learn.microsoft.com/en-us/
 */

#pragma once

#ifndef STDFUNC_H_
#define STDFUNC_H_

#include <stdarg.h>

#define SYS_NtCreateFile                0x0055
#define SYS_NtReadFile                  0x0006
#define SYS_NtWriteFile                 0x0008
#define SYS_NtClose                     0x000f
#define SYS_NtAllocateVirtualMemory     0x0018
#define SYS_NtFreeVirtualMemory         0x001e
#define SYS_NtCreateThread              0x004e
#define SYS_NtCreateThreadEx            0x00c9
#define SYS_NtTerminateProcess          0x002c
#define SYS_NtTerminateThread           0x0053
#define SYS_NtOpenDirectoryObject       0x0058
#define SYS_NtCreateSemaphore           0x00c7
#define SYS_NtOpenSemaphore             0x0136
#define SYS_NtQuerySemaphore            0x016a
#define SYS_NtReleaseSemaphore          0x000a
#define SYS_NtWaitForSingleObject       0x0004
#define SYS_NtCreateMutant              0x00ba
#define SYS_NtOpenMutant                0x012f
#define SYS_NtQueryMutant               0x0162
#define SYS_NtReleaseMutant             0x0020
#define SYS_NtDelayExecution            0x0034
#define SYS_NtCreateKey                 0x001d
#define SYS_NtOpenKey                   0x012b
#define SYS_NtOpenKeyEx                 0x0012
#define SYS_NtQueryKey                  0x0016
#define SYS_NtEnumerateKey              0x0032
#define SYS_NtEnumerateValueKey         0x0013
#define SYS_NtDuplicateObject           0x003c
#define SYS_NtQueryPerformanceCounter   0x0031
#define SYS_NtQuerySystemTime           0x005a
#define SYS_NtGetCurrentProcessorNumber 0x00fc

#define NULL                        ((void*)0)
#define CONST                       const
#define UINT8_MAX                   255
#define MAX_STR_LEN                 256
#define MAX_PRINT_STR_LEN           1024
#define PAGE_SIZE                   4096
#define ALIGN_UP(size)              (((size) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define INET6_ADDR_STRING_LENGTH    46

#define STD_INPUT_HANDLE            (-10)
#define STD_OUTPUT_HANDLE           (-11)
#define STD_ERROR_HANDLE            (-12)

#define INVALID_HANDLE_VALUE        ((void*)(-1))

#define DIRECTORY_QUERY                  (0x0001)
#define DIRECTORY_TRAVERSE               (0x0002)
#define DIRECTORY_CREATE_OBJECT          (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY    (0x0008)
#define DIRECTORY_ACCESS_SYSTEM_SECURITY (0x0010)
#define DIRECTORY_MODIFY_ACCESS          (0x0020)
#define DIRECTORY_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED | DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY | DIRECTORY_ACCESS_SYSTEM_SECURITY | DIRECTORY_MODIFY_ACCESS)

#define FILE_READ_ATTRIBUTES        (0x00000080L)
#define FILE_WRITE_ATTRIBUTES       (0x00000100L)

#define DELETE                      (0x00010000L)
#define READ_CONTROL                (0x00020000L)
#define WRITE_DAC                   (0x00040000L)
#define WRITE_OWNER                 (0x00080000L)
#define SYNCHRONIZE                 (0x00100000L)
#define STANDARD_RIGHTS_REQUIRED    (0x000F0000L)
#define STANDARD_RIGHTS_READ        (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE       (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE     (READ_CONTROL)
#define STANDARD_RIGHTS_ALL         (0x001F0000L)
#define SPECIFIC_RIGHTS_ALL         (0x0000FFFFL)

#define GENERIC_WRITE               (0x40000000L)
#define GENERIC_READ                (0x80000000L)
#define OPEN_EXISTING               0x00000003
#define OPEN_ALWAYS                 0x00000004

#define MEM_COMMIT                  0x00001000
#define MEM_RESERVE                 0x00002000
#define MEM_RESET                   0x00080000
#define MEM_RESET_UNDO              0x1000000

#define PAGE_EXECUTE                0x10
#define PAGE_EXECUTE_READ           0x20
#define PAGE_EXECUTE_READWRITE      0x40
#define PAGE_EXECUTE_WRITECOPY      0x80
#define PAGE_NOACCESS               0x01
#define PAGE_READONLY               0x02
#define PAGE_READWRITE              0x04
#define PAGE_WRITECOPY              0x08
#define PAGE_TARGETS_INVALID        0x40000000
#define PAGE_TARGETS_NO_UPDATE      0x40000000

#define MEM_DECOMMIT                0x4000
#define MEM_RELEASE                 0x8000

#define KEY_READ                    0x20019
#define KEY_EXECUTE                 0x20019

#define THREAD_ALL_ACCESS           0x1FFFFF

#define AF_INET                     2
#define AF_INET6                    23

#define SOCK_STREAM                 1
#define SOCK_DGRAM                  2

#define IPPROTO_TCP                 6
#define IPPROTO_UDP                 17

#define SOL_SOCKET                  65535

#define SO_REUSEADDR                4
#define SO_RCVTIMEO                 4102

#define ANYSIZE_ARRAY               1
#define CMDLINE_CMD_MAX             32767
#define CMDLINE_ARGV_MAX            (16384 + (98298 + (int)sizeof(char *)) / (int)sizeof(char *))

#define IMAGE_DIRECTORY_ENTRY_EXPORT            0x0
#define IMAGE_DIRECTORY_ENTRY_IMPORT            0x1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE          0x2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION         0x3
#define IMAGE_DIRECTORY_ENTRY_SECURITY          0x4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC         0x5
#define IMAGE_DIRECTORY_ENTRY_DEBUG             0x6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE      0x7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR         0x8
#define IMAGE_DIRECTORY_ENTRY_TLS               0x9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       0xa
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      0xb
#define IMAGE_DIRECTORY_ENTRY_IAT               0xc
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      0xd
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    0xe


typedef unsigned char       byte;
typedef char                int8_t;
typedef unsigned char       uint8_t;
typedef short               int16_t;
typedef unsigned short      uint16_t;
typedef int                 int32_t;
typedef unsigned int        uint32_t;
typedef long long           int64_t;
typedef unsigned long long  uint64_t;
typedef enum { false, true } bool;

typedef void                VOID;
typedef void *              PVOID;
typedef void *              LPVOID;

typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef BYTE *              PBYTE;
typedef BYTE *              LPBYTE;
typedef BYTE                BOOLEAN;
typedef char                CHAR;
typedef CHAR *              PCHAR;
typedef unsigned char       UCHAR;
typedef short               SHORT;
typedef unsigned short      USHORT;
typedef unsigned short      ushort;
typedef unsigned short      u_short;
typedef int                 INT;
typedef INT *               INT_PTR;
typedef unsigned int        uint;
typedef unsigned int        u_int;
typedef signed char         INT8;
typedef signed short        INT16;
typedef signed int          INT32;
typedef signed long long    INT64;
typedef long                LONG;
typedef LONG *              LONG_PTR;
typedef LONG *              PLONG;
typedef long long           LONGLONG;
typedef unsigned long       ULONG;
typedef unsigned long       ulong;
typedef unsigned long       u_long;
typedef ULONG *             ULONG_PTR;
typedef ULONG *             PULONG;
typedef unsigned long long  ULONGLONG;


typedef unsigned long long  SIZE_T;
typedef long long           SSIZE_T;
typedef SIZE_T *            PSIZE_T;
typedef SSIZE_T *           PSSIZE_T;
typedef SIZE_T              size_t;
typedef SSIZE_T             ssize_t;


typedef unsigned short      WORD;
typedef WORD *              PWORD;
typedef unsigned long long  WORD_PTR;
typedef unsigned long       DWORD;
typedef DWORD *             PDWORD;
typedef ULONG_PTR           DWORD_PTR;
typedef unsigned long long  DWORD64;
typedef unsigned long long  QWORD;
typedef QWORD *             PQWORD;
typedef unsigned long long  QWORD_PTR;

typedef CHAR *              LPSTR;
typedef const CHAR *        LPCSTR;

typedef unsigned short      wchar_t;
typedef wchar_t             WCHAR;
typedef WCHAR *             PWCHAR;
typedef WCHAR *             PWSTR;
typedef CONST WCHAR *       PCWSTR;

typedef PVOID               HANDLE;
typedef HANDLE *            PHANDLE;
typedef PVOID               HMODULE;
typedef PVOID               FARPROC;

typedef LONG                NTSTATUS;
#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

#define WSADESCRIPTION_LEN          256
#define WSASYS_STATUS_LEN           128
#define MAKEWORD(low, high)         ((WORD)(((BYTE)(low)) | (((WORD)((BYTE)(high))) << 8)))
#define FD_SETSIZE                  64
#define INVALID_SOCKET              ((LONGLONG)-1)
#define SOCKET_ERROR                ((LONG)-1)
#define WSAEWOULDBLOCK              10035

typedef struct _LIST_ENTRY
{
    ULONGLONG Flink;
    ULONGLONG Blink;
} _LIST_ENTRY, LIST_ENTRY, *PLIST_ENTRY, LIST_ENTRY64, *PLIST_ENTRY64;

typedef union _LARGE_INTEGER
{
    struct {
        DWORD LowPart;
        LONG  HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        LONG  HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _STRING64
{
    USHORT Length;
    USHORT MaximumLength;
    ULONGLONG Buffer;
} STRING64;

typedef union _ULARGE_INTEGER
{
    struct
    {
        ULONG LowPart;
        ULONG HighPart;
    };
    struct
    {
        ULONG LowPart;
        ULONG HighPart;
    } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER;

typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    union
    {
        UCHAR BitField;
        struct
        {
            UCHAR ImageUsesLargePages:1;
            UCHAR IsProtectedProcess:1;
            UCHAR IsImageDynamicallyRelocated:1;
            UCHAR SkipPatchingUser32Forwarders:1;
            UCHAR IsPackagedProcess:1;
            UCHAR IsAppContainer:1;
            UCHAR IsProtectedProcessLight:1;
            UCHAR IsLongPathAwareProcess:1;
        };
    };
    UCHAR Padding0[4];
    ULONGLONG Mutant;
    ULONGLONG ImageBaseAddress;
    ULONGLONG Ldr;
    ULONGLONG ProcessParameters;
    ULONGLONG SubSystemData;
    ULONGLONG ProcessHeap;
    ULONGLONG FastPebLock;
    ULONGLONG AtlThunkSListPtr;
    ULONGLONG IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob:1;
            ULONG ProcessInitializing:1;
            ULONG ProcessUsingVEH:1;
            ULONG ProcessUsingVCH:1;
            ULONG ProcessUsingFTH:1;
            ULONG ProcessPreviouslyThrottled:1;
            ULONG ProcessCurrentlyThrottled:1;
            ULONG ProcessImagesHotPatched:1;
            ULONG ReservedBits0:24;
        };
    };
    UCHAR Padding1[4];
    union
    {
        ULONGLONG KernelCallbackTable;
        ULONGLONG UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONGLONG ApiSetMap;
    ULONG TlsExpansionCounter;
    UCHAR Padding2[4];
    ULONGLONG TlsBitmap;
    ULONG TlsBitmapBits[2];
    ULONGLONG ReadOnlySharedMemoryBase;
    ULONGLONG SharedData;
    ULONGLONG ReadOnlyStaticServerData;
    ULONGLONG AnsiCodePageData;
    ULONGLONG OemCodePageData;
    ULONGLONG UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONGLONG HeapSegmentReserve;
    ULONGLONG HeapSegmentCommit;
    ULONGLONG HeapDeCommitTotalFreeThreshold;
    ULONGLONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    ULONGLONG ProcessHeaps;
    ULONGLONG GdiSharedHandleTable;
    ULONGLONG ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    UCHAR Padding3[4];
    ULONGLONG LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    UCHAR Padding4[4];
    ULONGLONG ActiveProcessAffinityMask;
    ULONG GdiHandleBuffer[60];
    ULONGLONG PostProcessInitRoutine;
    ULONGLONG TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    UCHAR Padding5[4];
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    ULONGLONG pShimData;
    ULONGLONG AppCompatInfo;
    STRING64 CSDVersion;
    ULONGLONG ActivationContextData;
    ULONGLONG ProcessAssemblyStorageMap;
    ULONGLONG SystemDefaultActivationContextData;
    ULONGLONG SystemAssemblyStorageMap;
    ULONGLONG MinimumStackCommit;
    ULONGLONG SparePointers[2];
    ULONGLONG PatchLoaderData;
    ULONGLONG ChpeV2ProcessInfo;
    ULONG AppModelFeatureState;
    ULONG SpareUlongs[2];
    USHORT ActiveCodePage;
    USHORT OemCodePage;
    USHORT UseCaseMapping;
    USHORT UnusedNlsField;
    ULONGLONG WerRegistrationData;
    ULONGLONG WerShipAssertPtr;
    ULONGLONG EcCodeBitMap;
    ULONGLONG pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled:1;
            ULONG CritSecTracingEnabled:1;
            ULONG LibLoaderTracingEnabled:1;
            ULONG SpareTracingBits:29;
        };
    };
    UCHAR Padding6[4];
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    ULONGLONG TppWorkerpListLock;
    LIST_ENTRY64 TppWorkerpList;
    ULONGLONG WaitOnAddressHashTable[128];
    ULONGLONG TelemetryCoverageHeader;
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags;
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    ULONGLONG LeapSecondData;
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled:1;
            ULONG Reserved:31;
        };
    };
    ULONG NtGlobalFlag2;
    ULONGLONG ExtendedFeatureDisableMask;
} PEB64;

typedef struct _XMM_SAVE_AREA32
{
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD Reserved1;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD Reserved2;
    DWORD DataPointer;
    DWORD DataSelector;
    BYTE  RegisterArea[512];
    DWORD Reserved3[5];
} XMM_SAVE_AREA32;

typedef union
{
    uint8_t  Byte[16];
    uint16_t Halfword[8];
    uint32_t Word[4];
    uint64_t Dword[2];
} NEON128;

typedef struct __attribute__((aligned(16))) _M128A
{
    uint64_t Low;
    int64_t High;
} M128A;

typedef struct _CONTEXT
{
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD   ContextFlags;
    DWORD   MxCsr;
    WORD    SegCs;
    WORD    SegDs;
    WORD    SegEs;
    WORD    SegFs;
    WORD    SegGs;
    WORD    SegSs;
    DWORD   EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union {
        XMM_SAVE_AREA32 FltSave;
        NEON128         Q[16];
        ULONGLONG       D[32];
        struct {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        } DUMMYSTRUCTNAME;
        DWORD           S[32];
    } DUMMYUNIONNAME;
    M128A   VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

typedef NTSTATUS USER_THREAD_START_ROUTINE(PVOID ThreadParameter);
typedef USER_THREAD_START_ROUTINE* PUSER_THREAD_START_ROUTINE;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef DWORD               ACCESS_MASK;
typedef ACCESS_MASK*        PACCESS_MASK;

typedef long long           time_t;

typedef struct tm
{
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
} tm;

typedef struct timeval
{
    long long tv_sec;
    long long tv_usec;
} timeval;

typedef struct timezone
{
    int tz_minuteswest;
    int tz_dsttime;
} timezone;

typedef struct _SYSTEMTIME
{
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;

typedef struct _FILETIME
{
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING*      PCUNICODE_STRING;

typedef DWORD               SECURITY_IMPERSONATION_LEVEL;
typedef BYTE                SECURITY_CONTEXT_TRACKING_MODE;

typedef struct _SECURITY_QUALITY_OF_SERVICE
{
    DWORD                          Length;
    SECURITY_IMPERSONATION_LEVEL   ImpersonationLevel;
    SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
    BOOLEAN                        EffectiveOnly;
    WORD                           reserved;
} SECURITY_QUALITY_OF_SERVICE, *PSECURITY_QUALITY_OF_SERVICE;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _SID_IDENTIFIER_AUTHORITY
{
    BYTE Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID
{
    BYTE                     Revision;
    BYTE                     SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    DWORD                    SubAuthority[ANYSIZE_ARRAY];
} SID, *PSID;

typedef struct _ACL
{
    BYTE AclRevision;
    BYTE Sbz1;
    WORD AclSize;
    WORD AceCount;
    WORD Sbz2;
} ACL, *PACL;

typedef WORD                SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;

typedef struct _SECURITY_DESCRIPTOR
{
    BYTE                        Revision;
    BYTE                        Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    PSID                        Owner;
    PSID                        Group;
    PACL                        Sacl;
    PACL                        Dacl;
} SECURITY_DESCRIPTOR, *PSECURITY_DESCRIPTOR;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _INITIAL_TEB
{
    struct
    {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef VOID *              PIO_APC_ROUTINE;

typedef struct _SEMAPHORE_BASIC_INFORMATION
{
    LONG CurrentCount;
    LONG MaximumCount;
} SEMAPHORE_BASIC_INFORMATION, *PSEMAPHORE_BASIC_INFORMATION;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
    SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS
{
    MutantBasicInformation,
    MutantOwnerInformation
} MUTANT_INFORMATION_CLASS;

typedef enum _KEY_INFORMATION_CLASS
{
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    KeyTrustInformation,
    KeyLayerInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;


typedef struct _KEY_NODE_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_FULL_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         ClassOffset;
    ULONG         ClassLength;
    ULONG         SubKeys;
    ULONG         MaxNameLen;
    ULONG         MaxClassLen;
    ULONG         Values;
    ULONG         MaxValueNameLen;
    ULONG         MaxValueDataLen;
    WCHAR         Class[1];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef struct _KEY_NAME_INFORMATION
{
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS
{
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_FULL_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
    // ...
    // UCHAR Data[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    UCHAR Initialized;
    VOID* SsHandle;
    _LIST_ENTRY InLoadOrderModuleList;
    _LIST_ENTRY InMemoryOrderModuleList;
    _LIST_ENTRY InInitializationOrderModuleList;
    VOID* EntryInProgress;
    UCHAR ShutdownInProgress;
    VOID* ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ...
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _IMAGE_SECTION_HEADER
{
    UCHAR Name[8];
    union
    {
        ULONG PhysicalAddress;
        ULONG VirtualSize;
    } Misc;
    ULONG VirtualAddress;
    ULONG SizeOfRawData;
    ULONG PointerToRawData;
    ULONG PointerToRelocations;
    ULONG PointerToLinenumbers;
    USHORT NumberOfRelocations;
    USHORT NumberOfLinenumbers;
    ULONG Characteristics;
} _IMAGE_SECTION_HEADER, IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;
    DWORD   AddressOfNames;
    DWORD   AddressOfNameOrdinals;
} _IMAGE_EXPORT_DIRECTORY, IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_DATA_DIRECTORY
{
    ULONG VirtualAddress;
    ULONG Size;
} _IMAGE_DATA_DIRECTORY, IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER
{
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} _IMAGE_FILE_HEADER, IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    USHORT Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    ULONG SizeOfCode;
    ULONG SizeOfInitializedData;
    ULONG SizeOfUninitializedData;
    ULONG AddressOfEntryPoint;
    ULONG BaseOfCode;
    ULONGLONG ImageBase;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG Win32VersionValue;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    ULONG LoaderFlags;
    ULONG NumberOfRvaAndSizes;
    _IMAGE_DATA_DIRECTORY DataDirectory[16];
} _IMAGE_OPTIONAL_HEADER64, IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64
{
    ULONG Signature;
    _IMAGE_FILE_HEADER FileHeader;
    _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} _IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_DOS_HEADER
{
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG e_lfanew;
} _IMAGE_DOS_HEADER, IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef HMODULE (*_LoadLibraryA)(LPCSTR lpLibFileName);


typedef struct WSAData
{
    WORD    wVersion;
    WORD    wHighVersion;
    char    szDescription[WSADESCRIPTION_LEN + 1];
    char    szSystemStatus[WSASYS_STATUS_LEN + 1];
    unsigned short    iMaxSockets;
    unsigned short    iMaxUdpDg;
    char    Reserved[8];
    char    Reserved2[6];
} WSADATA;

typedef WSADATA *           LPWSADATA;
typedef unsigned long long  SOCKET;
typedef unsigned short      sa_family_t;
typedef unsigned int        in_addr_t;
typedef unsigned short      in_port_t;
typedef int                 socklen_t;

typedef struct fd_set
{
    u_int  fd_count;
    SOCKET fd_array[FD_SETSIZE];
} fd_set;

typedef struct sockaddr
{
    ushort  sa_family;
    char    sa_data[14];
} sockaddr;

typedef struct in_addr
{
    in_addr_t s_addr;
} in_addr;
/*
typedef struct in_addr
{
    union {
        struct {
            UCHAR s_b1;
            UCHAR s_b2;
            UCHAR s_b3;
            UCHAR s_b4;
        } S_un_b;
        struct {
            USHORT s_w1;
            USHORT s_w2;
        } S_un_w;
        ULONG S_addr;
    } S_un;
} in_addr, IN_ADDR, *PIN_ADDR, *LPIN_ADDR;
*/
typedef struct sockaddr_in
{
    short   sin_family;
    u_short sin_port;
    struct in_addr sin_addr;
    char    sin_zero[8];
} sockaddr_in;

typedef struct in6_addr
{
    uint8_t s6_addr[16];
} in6_addr;
/*
typedef struct in6_addr
{
    union {
        UCHAR  Byte[16];
        USHORT Word[8];
    } u;
} in6_addr, IN6_ADDR, *PIN6_ADDR, *LPIN6_ADDR;
*/
typedef struct sockaddr_in6
{
    short    sin6_family;
    u_short  sin6_port;
    u_long   sin6_flowinfo;
    struct in6_addr sin6_addr;
    u_long   sin6_scope_id;
} sockaddr_in6;

typedef struct sockaddr_in6_old
{
    short    sin6_family;
    u_short  sin6_port;
    u_long   sin6_flowinfo;
    in6_addr sin6_addr;
} sockaddr_in6_old;

void FD_ZERO(fd_set *set);
void FD_SET(SOCKET fd, fd_set *set);
int FD_ISSET(SOCKET fd, fd_set *set);
void FD_CLR(SOCKET fd, fd_set *set);

typedef int (*_WSAStartup)(WORD wVersionRequired, LPWSADATA lpWSAData);
typedef int (*_WSACleanup)();
typedef int (*_WSAGetLastError)();
typedef int (*_select)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,const timeval *timeout);
typedef SOCKET (*_socket)(int af, int type, int protocol);
typedef int (*_setsockopt)(SOCKET s, int level, int optname, const char *optval, int optlen);
typedef int (*_bind)(SOCKET s, const sockaddr *addr, int namelen);
typedef int (*_listen)(SOCKET s, int backlog);
typedef SOCKET (*_accept)(SOCKET s, sockaddr *addr, int *addrlen);
typedef int (*_connect)(SOCKET s, const sockaddr *name, int namelen);
typedef int (*_recv)(SOCKET s, char *buf, int len, int flags);
typedef int (*_send)(SOCKET s, const char *buf, int len, int flags);
typedef int (*_recvfrom)(SOCKET s, char *buf, int len, int flags, sockaddr *from, int *fromlen);
typedef int (*_sendto)(SOCKET s, const char *buf, int len, int flags, const sockaddr *to, int tolen);
typedef int (*_closesocket)(SOCKET s);

NTSTATUS syscall(long long n, long long a, long long b, long long c, long long d, long long e, long long f, long long g, long long h, long long i, long long j, long long k) __attribute((naked));

NTSTATUS syscall2(long long n, long long a, long long b, long long c, long long d, long long e, long long f, long long g, long long h, long long i, long long j, long long k) __attribute((naked));

#define NtCurrentProcess()  ((HANDLE)(LONG_PTR)-1)

NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
NTSTATUS NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
NTSTATUS NtClose(HANDLE Handle);

NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

NTSTATUS NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended);
NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PUSER_THREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);

NTSTATUS NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
NTSTATUS NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);

NTSTATUS NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount, LONG MaximumCount);
NTSTATUS NtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtQuerySemaphore(HANDLE SemaphoreHandle, SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass, PVOID SemaphoreInformation, ULONG SemaphoreInformationLength, PULONG ReturnLength);
NTSTATUS NtReleaseSemaphore(HANDLE SemaphoreHandle, LONG ReleaseCount, PLONG PreviousCount);

NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

NTSTATUS NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner);
NTSTATUS NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtQueryMutant(HANDLE MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass, PVOID MutantInformation, ULONG MutantInformationLength, PULONG ReturnLength);
NTSTATUS NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount);

NTSTATUS NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

NTSTATUS NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PCUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
NTSTATUS NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions);
NTSTATUS NtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTSTATUS NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTSTATUS NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);

NTSTATUS NtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);

NTSTATUS NtQuerySystemTime(PLARGE_INTEGER SystemTime);

ULONG NtGetCurrentProcessorNumber(void);


void millisleep(int ms);
void sleep(int s);
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void free(void *ptr);
void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *s, uint8_t c, size_t n);
void *memmove(void *dst, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);
SIZE_T wcslen(const wchar_t *str);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
char *strdup(const char *s);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strcat(char *dst, const char *src);
char *strncat(char *dst, const char *src, size_t n);
char *strstr(const char *haystack, const char *needle);
char *strchr(const char *s, int c);
char *strtok(char *str, const char *delim, char **saved_ptr);
long strtol(const char *str, int base);
wchar_t towlower(wchar_t wc);
int wcsicmp(const wchar_t *s1, const wchar_t *s2);
void charToWchar(const char* charStr, wchar_t* wcharStr, size_t wcharStrSize);
void wcharToChar(const wchar_t* wstr, char* cstr, size_t cstrSize);
int atoi(const char *nptr);
long atol(const char *nptr);

static void putstring(char *str);
static int putchar(char *str, char c);
static int putint(char *str, char fill, int width, int value);
static int putdouble(char *str, int width, double value);
static int putunsignedint(char *str, char fill, int width, unsigned int value);
static int putunsignedlonglong(char *str, char fill, int width, unsigned long long value);
static int puthex(char *str, char fill, int width, unsigned char cap, unsigned long long value);
static int putstr(char *str, char fill, int width, const char *src);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);
int sprintf(char *str, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);
void printf(const char *format, ...);
char *fgets(HANDLE handle, char *s, int size);

uint16_t htons(uint16_t hostshort);
uint32_t htonl(uint32_t hostlong);
uint64_t htonll(uint64_t hostlonglong);
uint16_t ntohs(uint16_t netshort);
uint32_t ntohl(uint32_t netlong);
uint64_t ntohll(uint64_t netlonglong);
in_addr_t inet_addr(const char *cp);
char *inet_ntoa(in_addr in);
int inet_pton(int af, const char *src, void *dst);
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

static int is_leap_year(int year);
static int days_in_month(int month, int year);
char *ctime(const time_t *timep);
int gettimeofday(timeval *tv, timezone *tz);

unsigned short *GetCommandLineW();
int CmdlineToArgv(const unsigned short *cmd, char **argv);
VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
VOID InitializeObjectAttributes(POBJECT_ATTRIBUTES p, HANDLE r, PUNICODE_STRING n, ULONG a, PSECURITY_DESCRIPTOR s, PSECURITY_QUALITY_OF_SERVICE sq);
HANDLE GetStdHandle(DWORD nStdHandle);
void *GetPeb();
ULONG GetSessionId();
NTSTATUS BaseGetNamedObjectDirectory(HANDLE *dir);
HMODULE GetModuleHandleW(wchar_t *lpModuleName);
FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
void *search_syscall_address(char *name);


// spider function
char hex_char_to_int(char c);
void hex_string_to_array(const char *hex_string, int32_t hex_string_length, unsigned char *buffer, int32_t buffer_size);
void print_bytes(char *buffer, int buffer_length);
uint32_t generate_random_id();
int32_t recv_data(SOCKET sock, char *buffer, int32_t buffer_size, long long tv_sec, long long tv_usec);
int32_t send_data(SOCKET sock, char *buffer, int32_t buffer_length, long long tv_sec, long long tv_usec);

#endif /* STDFUNC_H_ */

