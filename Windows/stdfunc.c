/*
 * Title:  stdfunc.c
 * Author: Shuichiro Endo
 */

/*
 * Reference:
 * https://nullprogram.com/blog/2022/02/18/
 * https://github.com/skeeto/scratch/blob/master/parsers/cmdline.c
 * https://www.vergiliusproject.com/kernels/x64/windows-11/25h2
 * https://ntdoc.m417z.com/
 * https://j00ru.vexillium.org/syscalls/nt/64/
 * https://learn.microsoft.com
 */

#include "stdfunc.h"

HANDLE stdin = NULL;
HANDLE stdout = NULL;
HANDLE rootdir = NULL;
HANDLE mallocaddress_mutex = NULL;
void *mallocaddress = (void *)0x25000000000;
void *syscalladdress = NULL;

_WSAStartup WSAStartup = NULL;
_WSACleanup WSACleanup = NULL;
_WSAGetLastError WSAGetLastError = NULL;
_socket socket = NULL;
_select select = NULL;
_setsockopt setsockopt = NULL;
_bind bind = NULL;
_listen listen = NULL;
_accept accept = NULL;
_connect connect = NULL;
_recv recv = NULL;
_send send = NULL;
_recvfrom recvfrom = NULL;
_sendto sendto = NULL;
_closesocket closesocket = NULL;

NTSTATUS syscall(long long n,
                 long long a,
                 long long b,
                 long long c,
                 long long d,
                 long long e,
                 long long f,
                 long long g,
                 long long h,
                 long long i,
                 long long j,
                 long long k)
{
    __asm__ __volatile__
    (
        "movq %%rcx, 0x8(%%rsp)\n"
        "movq %%rdx, 0x10(%%rsp)\n"
        "movq %%r8, 0x18(%%rsp)\n"
        "movq %%r9, 0x20(%%rsp)\n"
        "sub $0x60, %%rsp\n"
        "movq 0xc0(%%rsp), %%rcx\n"
        "movq %%rcx, 0x58(%%rsp)\n"
        "movq 0xb8(%%rsp), %%rcx\n"
        "movq %%rcx, 0x50(%%rsp)\n"
        "movq 0xb0(%%rsp), %%rcx\n"
        "movq %%rcx, 0x48(%%rsp)\n"
        "movq 0xa8(%%rsp), %%rcx\n"
        "movq %%rcx, 0x40(%%rsp)\n"
        "movq 0xa0(%%rsp), %%rcx\n"
        "movq %%rcx, 0x38(%%rsp)\n"
        "movq 0x98(%%rsp), %%rcx\n"
        "movq %%rcx, 0x30(%%rsp)\n"
        "movq 0x90(%%rsp), %%rcx\n"
        "movq %%rcx, 0x28(%%rsp)\n"
        "movq 0x88(%%rsp), %%r9\n"
        "movq 0x80(%%rsp), %%r8\n"
        "movq 0x78(%%rsp), %%rdx\n"
        "movq 0x70(%%rsp), %%rcx\n"
        "movq %%rcx, %%r10\n"
        "movq 0x68(%%rsp), %%rax\n"
        "syscall\n"
        "add $0x60, %%rsp\n"
        "ret"
        :
        :
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "cc", "memory"
    );
}

NTSTATUS syscall2(long long n,
                  long long a,
                  long long b,
                  long long c,
                  long long d,
                  long long e,
                  long long f,
                  long long g,
                  long long h,
                  long long i,
                  long long j,
                  long long k)
{
    __asm__ __volatile__
    (
        "movq %%rcx, 0x8(%%rsp)\n"
        "movq %%rdx, 0x10(%%rsp)\n"
        "movq %%r8, 0x18(%%rsp)\n"
        "movq %%r9, 0x20(%%rsp)\n"
        "sub $0x60, %%rsp\n"
        "movq 0xc0(%%rsp), %%rcx\n"
        "movq %%rcx, 0x58(%%rsp)\n"
        "movq 0xb8(%%rsp), %%rcx\n"
        "movq %%rcx, 0x50(%%rsp)\n"
        "movq 0xb0(%%rsp), %%rcx\n"
        "movq %%rcx, 0x48(%%rsp)\n"
        "movq 0xa8(%%rsp), %%rcx\n"
        "movq %%rcx, 0x40(%%rsp)\n"
        "movq 0xa0(%%rsp), %%rcx\n"
        "movq %%rcx, 0x38(%%rsp)\n"
        "movq 0x98(%%rsp), %%rcx\n"
        "movq %%rcx, 0x30(%%rsp)\n"
        "movq 0x90(%%rsp), %%rcx\n"
        "movq %%rcx, 0x28(%%rsp)\n"
        "movq 0x88(%%rsp), %%r9\n"
        "movq 0x80(%%rsp), %%r8\n"
        "movq 0x78(%%rsp), %%rdx\n"
        "movq 0x70(%%rsp), %%rcx\n"
        "movq %%rcx, %%r10\n"
        "movq 0x68(%%rsp), %%rax\n"
        "movq %[syscalladdress], %%r11\n"
        "lea 0x7(%%rip), %%rcx\n"
        "movq %%rcx, (%%rsp)\n"
        "jmp *%%r11\n"
        "add $0x58, %%rsp\n"
        "ret"
        :
        : [syscalladdress] "m" (syscalladdress)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "cc", "memory"
    );
}

NTSTATUS NtCreateFile(PHANDLE FileHandle,
                      ACCESS_MASK DesiredAccess,
                      POBJECT_ATTRIBUTES ObjectAttributes,
                      PIO_STATUS_BLOCK IoStatusBlock,
                      PLARGE_INTEGER AllocationSize,
                      ULONG FileAttributes,
                      ULONG ShareAccess,
                      ULONG CreateDisposition,
                      ULONG CreateOptions,
                      PVOID EaBuffer,
                      ULONG EaLength)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtCreateFile,
                         (long long)FileHandle,
                         (long long)DesiredAccess,
                         (long long)ObjectAttributes,
                         (long long)IoStatusBlock,
                         (long long)AllocationSize,
                         (long long)FileAttributes,
                         (long long)ShareAccess,
                         (long long)CreateDisposition,
                         (long long)CreateOptions,
                         (long long)EaBuffer,
                         (long long)EaLength);
    }else
    {
        status = syscall2((long long)SYS_NtCreateFile,
                          (long long)FileHandle,
                          (long long)DesiredAccess,
                          (long long)ObjectAttributes,
                          (long long)IoStatusBlock,
                          (long long)AllocationSize,
                          (long long)FileAttributes,
                          (long long)ShareAccess,
                          (long long)CreateDisposition,
                          (long long)CreateOptions,
                          (long long)EaBuffer,
                          (long long)EaLength);
    }

    return status;
}

NTSTATUS NtReadFile(HANDLE FileHandle,
                    HANDLE Event,
                    PIO_APC_ROUTINE ApcRoutine,
                    PVOID ApcContext,
                    PIO_STATUS_BLOCK IoStatusBlock,
                    PVOID Buffer,
                    ULONG Length,
                    PLARGE_INTEGER ByteOffset,
                    PULONG Key)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtReadFile,
                         (long long)FileHandle,
                         (long long)Event,
                         (long long)ApcRoutine,
                         (long long)ApcContext,
                         (long long)IoStatusBlock,
                         (long long)Buffer,
                         (long long)Length,
                         (long long)ByteOffset,
                         (long long)Key,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtReadFile,
                          (long long)FileHandle,
                          (long long)Event,
                          (long long)ApcRoutine,
                          (long long)ApcContext,
                          (long long)IoStatusBlock,
                          (long long)Buffer,
                          (long long)Length,
                          (long long)ByteOffset,
                          (long long)Key,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtWriteFile(HANDLE FileHandle,
                     HANDLE Event,
                     PIO_APC_ROUTINE ApcRoutine,
                     PVOID ApcContext,
                     PIO_STATUS_BLOCK IoStatusBlock,
                     PVOID Buffer,
                     ULONG Length,
                     PLARGE_INTEGER ByteOffset,
                     PULONG Key)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtWriteFile,
                         (long long)FileHandle,
                         (long long)Event,
                         (long long)ApcRoutine,
                         (long long)ApcContext,
                         (long long)IoStatusBlock,
                         (long long)Buffer,
                         (long long)Length,
                         (long long)ByteOffset,
                         (long long)Key,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtWriteFile,
                          (long long)FileHandle,
                          (long long)Event,
                          (long long)ApcRoutine,
                          (long long)ApcContext,
                          (long long)IoStatusBlock,
                          (long long)Buffer,
                          (long long)Length,
                          (long long)ByteOffset,
                          (long long)Key,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtClose(HANDLE Handle)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtClose,
                         (long long)Handle,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtClose,
                          (long long)Handle,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle,
                                 PVOID *BaseAddress,
                                 ULONG_PTR ZeroBits,
                                 PSIZE_T RegionSize,
                                 ULONG AllocationType,
                                 ULONG Protect)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtAllocateVirtualMemory,
                         (long long)ProcessHandle,
                         (long long)BaseAddress,
                         (long long)ZeroBits,
                         (long long)RegionSize,
                         (long long)AllocationType,
                         (long long)Protect,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtAllocateVirtualMemory,
                          (long long)ProcessHandle,
                          (long long)BaseAddress,
                          (long long)ZeroBits,
                          (long long)RegionSize,
                          (long long)AllocationType,
                          (long long)Protect,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle,
                             PVOID *BaseAddress,
                             PSIZE_T RegionSize,
                             ULONG FreeType)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtFreeVirtualMemory,
                         (long long)ProcessHandle,
                         (long long)BaseAddress,
                         (long long)RegionSize,
                         (long long)FreeType,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtFreeVirtualMemory,
                          (long long)ProcessHandle,
                          (long long)BaseAddress,
                          (long long)RegionSize,
                          (long long)FreeType,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}


NTSTATUS NtCreateThread(PHANDLE ThreadHandle,
                        ACCESS_MASK DesiredAccess,
                        PCOBJECT_ATTRIBUTES ObjectAttributes,
                        HANDLE ProcessHandle,
                        PCLIENT_ID ClientId,
                        PCONTEXT ThreadContext,
                        PINITIAL_TEB InitialTeb,
                        BOOLEAN CreateSuspended)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtCreateThread,
                         (long long)ThreadHandle,
                         (long long)DesiredAccess,
                         (long long)ObjectAttributes,
                         (long long)ProcessHandle,
                         (long long)ClientId,
                         (long long)ThreadContext,
                         (long long)InitialTeb,
                         (long long)CreateSuspended,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtCreateThread,
                          (long long)ThreadHandle,
                          (long long)DesiredAccess,
                          (long long)ObjectAttributes,
                          (long long)ProcessHandle,
                          (long long)ClientId,
                          (long long)ThreadContext,
                          (long long)InitialTeb,
                          (long long)CreateSuspended,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle,
                          ACCESS_MASK DesiredAccess,
                          PCOBJECT_ATTRIBUTES ObjectAttributes,
                          HANDLE ProcessHandle,
                          PUSER_THREAD_START_ROUTINE StartRoutine,
                          PVOID Argument,
                          ULONG CreateFlags,
                          SIZE_T ZeroBits,
                          SIZE_T StackSize,
                          SIZE_T MaximumStackSize,
                          PPS_ATTRIBUTE_LIST AttributeList)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtCreateThreadEx,
                         (long long)ThreadHandle,
                         (long long)DesiredAccess,
                         (long long)ObjectAttributes,
                         (long long)ProcessHandle,
                         (long long)StartRoutine,
                         (long long)Argument,
                         (long long)CreateFlags,
                         (long long)ZeroBits,
                         (long long)StackSize,
                         (long long)MaximumStackSize,
                         (long long)AttributeList);
    }else
    {
        status = syscall2((long long)SYS_NtCreateThreadEx,
                          (long long)ThreadHandle,
                          (long long)DesiredAccess,
                          (long long)ObjectAttributes,
                          (long long)ProcessHandle,
                          (long long)StartRoutine,
                          (long long)Argument,
                          (long long)CreateFlags,
                          (long long)ZeroBits,
                          (long long)StackSize,
                          (long long)MaximumStackSize,
                          (long long)AttributeList);
    }

    return status;
}

NTSTATUS NtTerminateProcess(HANDLE ProcessHandle,
                            NTSTATUS ExitStatus)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtTerminateThread,
                         (long long)ProcessHandle,
                         (long long)ExitStatus,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtTerminateThread,
                          (long long)ProcessHandle,
                          (long long)ExitStatus,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtTerminateThread(HANDLE ThreadHandle,
                           NTSTATUS ExitStatus)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtTerminateThread,
                         (long long)ThreadHandle,
                         (long long)ExitStatus,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtTerminateThread,
                          (long long)ThreadHandle,
                          (long long)ExitStatus,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}



NTSTATUS NtOpenDirectoryObject(PHANDLE DirectoryHandle,
                               ACCESS_MASK DesiredAccess,
                               POBJECT_ATTRIBUTES ObjectAttributes)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtOpenDirectoryObject,
                         (long long)DirectoryHandle,
                         (long long)DesiredAccess,
                         (long long)ObjectAttributes,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtOpenDirectoryObject,
                          (long long)DirectoryHandle,
                          (long long)DesiredAccess,
                          (long long)ObjectAttributes,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtCreateSemaphore(PHANDLE SemaphoreHandle,
                           ACCESS_MASK DesiredAccess,
                           PCOBJECT_ATTRIBUTES ObjectAttributes,
                           LONG InitialCount,
                           LONG MaximumCount)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtCreateSemaphore,
                         (long long)SemaphoreHandle,
                         (long long)DesiredAccess,
                         (long long)ObjectAttributes,
                         (long long)InitialCount,
                         (long long)MaximumCount,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtCreateSemaphore,
                          (long long)SemaphoreHandle,
                          (long long)DesiredAccess,
                          (long long)ObjectAttributes,
                          (long long)InitialCount,
                          (long long)MaximumCount,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;

}

NTSTATUS NtOpenSemaphore(PHANDLE SemaphoreHandle,
                         ACCESS_MASK DesiredAccess,
                         PCOBJECT_ATTRIBUTES ObjectAttributes)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtOpenSemaphore,
                         (long long)SemaphoreHandle,
                         (long long)DesiredAccess,
                         (long long)ObjectAttributes,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtOpenSemaphore,
                          (long long)SemaphoreHandle,
                          (long long)DesiredAccess,
                          (long long)ObjectAttributes,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtQuerySemaphore(HANDLE SemaphoreHandle,
                          SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
                          PVOID SemaphoreInformation,
                          ULONG SemaphoreInformationLength,
                          PULONG ReturnLength)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtQuerySemaphore,
                         (long long)SemaphoreHandle,
                         (long long)SemaphoreInformationClass,
                         (long long)SemaphoreInformation,
                         (long long)SemaphoreInformationLength,
                         (long long)ReturnLength,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtQuerySemaphore,
                          (long long)SemaphoreHandle,
                          (long long)SemaphoreInformationClass,
                          (long long)SemaphoreInformation,
                          (long long)SemaphoreInformationLength,
                          (long long)ReturnLength,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtReleaseSemaphore(HANDLE SemaphoreHandle,
                            LONG ReleaseCount,
                            PLONG PreviousCount)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtReleaseSemaphore,
                         (long long)SemaphoreHandle,
                         (long long)ReleaseCount,
                         (long long)PreviousCount,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtReleaseSemaphore,
                          (long long)SemaphoreHandle,
                          (long long)ReleaseCount,
                          (long long)PreviousCount,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtWaitForSingleObject(HANDLE Handle,
                               BOOLEAN Alertable,
                               PLARGE_INTEGER Timeout)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtWaitForSingleObject,
                         (long long)Handle,
                         (long long)Alertable,
                         (long long)Timeout,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtWaitForSingleObject,
                          (long long)Handle,
                          (long long)Alertable,
                          (long long)Timeout,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtCreateMutant(PHANDLE MutantHandle,
                        ACCESS_MASK DesiredAccess,
                        PCOBJECT_ATTRIBUTES ObjectAttributes,
                        BOOLEAN InitialOwner)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtCreateMutant,
                         (long long)MutantHandle,
                         (long long)DesiredAccess,
                         (long long)ObjectAttributes,
                         (long long)InitialOwner,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtCreateMutant,
                          (long long)MutantHandle,
                          (long long)DesiredAccess,
                          (long long)ObjectAttributes,
                          (long long)InitialOwner,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtOpenMutant(PHANDLE MutantHandle,
                      ACCESS_MASK DesiredAccess,
                      PCOBJECT_ATTRIBUTES ObjectAttributes)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtOpenMutant,
                         (long long)MutantHandle,
                         (long long)DesiredAccess,
                         (long long)ObjectAttributes,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtOpenMutant,
                          (long long)MutantHandle,
                          (long long)DesiredAccess,
                          (long long)ObjectAttributes,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtQueryMutant(HANDLE MutantHandle,
                       MUTANT_INFORMATION_CLASS MutantInformationClass,
                       PVOID MutantInformation,
                       ULONG MutantInformationLength,
                       PULONG ReturnLength)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtQueryMutant,
                         (long long)MutantHandle,
                         (long long)MutantInformationClass,
                         (long long)MutantInformation,
                         (long long)MutantInformationLength,
                         (long long)ReturnLength,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtQueryMutant,
                          (long long)MutantHandle,
                          (long long)MutantInformationClass,
                          (long long)MutantInformation,
                          (long long)MutantInformationLength,
                          (long long)ReturnLength,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtReleaseMutant(HANDLE MutantHandle,
                         PLONG PreviousCount)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtReleaseMutant,
                         (long long)MutantHandle,
                         (long long)PreviousCount,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtReleaseMutant,
                          (long long)MutantHandle,
                          (long long)PreviousCount,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtDelayExecution(BOOLEAN Alertable,
                          PLARGE_INTEGER DelayInterval)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtDelayExecution,
                         (long long)Alertable,
                         (long long)DelayInterval,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtDelayExecution,
                          (long long)Alertable,
                          (long long)DelayInterval,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtCreateKey(PHANDLE KeyHandle,
                     ACCESS_MASK DesiredAccess,
                     POBJECT_ATTRIBUTES ObjectAttributes,
                     ULONG TitleIndex,
                     PCUNICODE_STRING Class,
                     ULONG CreateOptions,
                     PULONG Disposition)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtCreateKey,
                         (long long)KeyHandle,
                         (long long)DesiredAccess,
                         (long long)ObjectAttributes,
                         (long long)TitleIndex,
                         (long long)Class,
                         (long long)CreateOptions,
                         (long long)Disposition,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtCreateKey,
                          (long long)KeyHandle,
                          (long long)DesiredAccess,
                          (long long)ObjectAttributes,
                          (long long)TitleIndex,
                          (long long)Class,
                          (long long)CreateOptions,
                          (long long)Disposition,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtOpenKey(PHANDLE KeyHandle,
                   ACCESS_MASK DesiredAccess,
                   POBJECT_ATTRIBUTES ObjectAttributes)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtOpenKey,
                         (long long)KeyHandle,
                         (long long)DesiredAccess,
                         (long long)ObjectAttributes,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtOpenKey,
                          (long long)KeyHandle,
                          (long long)DesiredAccess,
                          (long long)ObjectAttributes,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtOpenKeyEx(PHANDLE KeyHandle,
                     ACCESS_MASK DesiredAccess,
                     POBJECT_ATTRIBUTES ObjectAttributes,
                     ULONG OpenOptions)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtOpenKeyEx,
                         (long long)KeyHandle,
                         (long long)DesiredAccess,
                         (long long)ObjectAttributes,
                         (long long)OpenOptions,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtOpenKeyEx,
                          (long long)KeyHandle,
                          (long long)DesiredAccess,
                          (long long)ObjectAttributes,
                          (long long)OpenOptions,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtQueryKey(HANDLE KeyHandle,
                    KEY_INFORMATION_CLASS KeyInformationClass,
                    PVOID KeyInformation,
                    ULONG Length,
                    PULONG ResultLength)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtQueryKey,
                         (long long)KeyHandle,
                         (long long)KeyInformationClass,
                         (long long)KeyInformation,
                         (long long)Length,
                         (long long)ResultLength,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtQueryKey,
                          (long long)KeyHandle,
                          (long long)KeyInformationClass,
                          (long long)KeyInformation,
                          (long long)Length,
                          (long long)ResultLength,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtEnumerateKey(HANDLE KeyHandle,
                        ULONG Index,
                        KEY_INFORMATION_CLASS KeyInformationClass,
                        PVOID KeyInformation,
                        ULONG Length,
                        PULONG ResultLength)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtEnumerateKey,
                         (long long)KeyHandle,
                         (long long)Index,
                         (long long)KeyInformationClass,
                         (long long)KeyInformation,
                         (long long)Length,
                         (long long)ResultLength,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtEnumerateKey,
                          (long long)KeyHandle,
                          (long long)Index,
                          (long long)KeyInformationClass,
                          (long long)KeyInformation,
                          (long long)Length,
                          (long long)ResultLength,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtEnumerateValueKey(HANDLE KeyHandle,
                             ULONG Index,
                             KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                             PVOID KeyValueInformation,
                             ULONG Length,
                             PULONG ResultLength)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtEnumerateValueKey,
                         (long long)KeyHandle,
                         (long long)Index,
                         (long long)KeyValueInformationClass,
                         (long long)KeyValueInformation,
                         (long long)Length,
                         (long long)ResultLength,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtEnumerateValueKey,
                          (long long)KeyHandle,
                          (long long)Index,
                          (long long)KeyValueInformationClass,
                          (long long)KeyValueInformation,
                          (long long)Length,
                          (long long)ResultLength,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter,
                                   PLARGE_INTEGER PerformanceFrequency)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtQueryPerformanceCounter,
                         (long long)PerformanceCounter,
                         (long long)PerformanceFrequency,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtQueryPerformanceCounter,
                          (long long)PerformanceCounter,
                          (long long)PerformanceFrequency,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

NTSTATUS NtQuerySystemTime(PLARGE_INTEGER SystemTime)
{
    NTSTATUS status;

    if(syscalladdress == NULL)
    {
        status = syscall((long long)SYS_NtQuerySystemTime,
                         (long long)SystemTime,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0,
                         (long long)0);
    }else
    {
        status = syscall2((long long)SYS_NtQuerySystemTime,
                          (long long)SystemTime,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0,
                          (long long)0);
    }

    return status;
}

ULONG NtGetCurrentProcessorNumber(void)
{
    ULONG pid;

    if(syscalladdress == NULL)
    {
        pid = syscall((long long)SYS_NtGetCurrentProcessorNumber,
                      (long long)0,
                      (long long)0,
                      (long long)0,
                      (long long)0,
                      (long long)0,
                      (long long)0,
                      (long long)0,
                      (long long)0,
                      (long long)0,
                      (long long)0,
                      (long long)0);
    }else
    {
        pid = syscall2((long long)SYS_NtGetCurrentProcessorNumber,
                       (long long)0,
                       (long long)0,
                       (long long)0,
                       (long long)0,
                       (long long)0,
                       (long long)0,
                       (long long)0,
                       (long long)0,
                       (long long)0,
                       (long long)0,
                       (long long)0);
    }

    return pid;
}

void FD_ZERO(fd_set *set)
{
    set->fd_count = 0;
}

void FD_SET(SOCKET fd, fd_set *set)
{
    set->fd_array[set->fd_count++] = fd;
}

int FD_ISSET(SOCKET fd, fd_set *set)
{
    for(int i = 0; i < set->fd_count; i++)
    {
        if(set->fd_array[i] == fd)
        {
            return 1;
        }
    }

    return 0;
}

void FD_CLR(SOCKET fd, fd_set *set)
{
    for(int i = 0; i < set->fd_count; i++)
    {
        if(set->fd_array[i] == fd)
        {
            set->fd_array[i] = set->fd_array[--set->fd_count];
            break;
        }
    }
}

void millisleep(int ms)
{
    NTSTATUS status;
    LARGE_INTEGER delayInterval;

    delayInterval.QuadPart = (LONGLONG)ms * -10000LL;

    status = NtDelayExecution(false, &delayInterval);
}

void sleep(int s)
{
    NTSTATUS status;
    LARGE_INTEGER delayInterval;

    delayInterval.QuadPart = (LONGLONG)s * -10000000LL;

    status = NtDelayExecution(false, &delayInterval);
}

void *malloc(size_t size)
{
    NTSTATUS status;
    void *ptr = NULL;
    size_t page_size = PAGE_SIZE;
    size_t total_size = 0;
    LONG previousCount_mutex = 0;

    if(size <= 0)
    {
        return NULL;
    }

    total_size = (size + (page_size - 1)) & ~(page_size - 1);

    status = NtWaitForSingleObject(mallocaddress_mutex, false, NULL);
    if(!NT_SUCCESS(status))
    {
        return NULL;
    }

    ptr = mallocaddress;

    status = NtAllocateVirtualMemory(NtCurrentProcess(), &ptr, 0, &total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(!NT_SUCCESS(status))
    {
        ptr = NULL;
    }else
    {
        mallocaddress = (void *)(((unsigned long long)mallocaddress + total_size + 0xFFFF) & ~(0xFFFF));
    }

    status = NtReleaseMutant(mallocaddress_mutex, &previousCount_mutex);

    return (char *)ptr;
}

void *calloc(size_t nmemb, size_t size)
{
    void *ptr = NULL;
    size_t total_size = 0;
    size_t i = 0;

    if(nmemb <= 0 || size <= 0)
    {
        return NULL;
    }

    total_size = nmemb * size;

    ptr = malloc(total_size);
    if(ptr)
    {
        for(i = 0; i < total_size; i++)
        {
            ((char *)ptr)[i] = 0;
        }
    }

    return ptr;
}

void free(void *ptr)
{
    NTSTATUS status;
    SIZE_T RegionSize = 0;

    status = NtFreeVirtualMemory(NtCurrentProcess(), &ptr, &RegionSize, MEM_RELEASE);
}

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *dst_addr = (uint8_t *)dst;
    uint8_t *src_addr = (uint8_t *)src;
    size_t i = 0;

    for(i = 0; i < n; i++)
    {
        *dst_addr++ = *src_addr++;
    }

    return dst;
}

void *memset(void *s, uint8_t c, size_t n)
{
    uint8_t *s_addr = (uint8_t *)s;
    size_t i = 0;

    for(i = 0; i < n; i++)
    {
        *s_addr++ = c;
    }

    return s;
}

void *memmove(void *dst, const void *src, size_t n)
{
    uint8_t *dst_addr = (uint8_t *)dst;
    uint8_t *src_addr = (uint8_t *)src;
    size_t i = 0;

    for(i = 0; i < n; i++)
    {
        *dst_addr++ = *src_addr++;
    }

    return dst;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
    uint8_t *s1_addr = (uint8_t *)s1;
    uint8_t *s2_addr = (uint8_t *)s2;

    while(n-- > 0)
    {
        if(*s1_addr++ != *s2_addr++)
        {
            return s1_addr[-1] < s2_addr[-1] ? -1 : 1;
        }
    }

    return 0;
}

size_t strlen(const char *s)
{
    size_t pos = 0;

    while(s[pos])
    {
        pos++;
    }

    return pos;
}

SIZE_T wcslen(const wchar_t *str)
{
    SIZE_T length = 0;

    while(*str++)
    {
        length++;
    }

    return length;
}

char *strcpy(char *dst, const char *src)
{
    char *ptr = dst;
    size_t i = 0;

    for(i = 0; src[i] != '\0'; i++, ptr++)
    {
        *ptr = *(src + i);
    }

    *ptr = '\0';

    return dst;
}

char *strncpy(char *dst, const char *src, size_t n)
{
    char *ptr = dst;
    size_t i = 0;

    for(i = 0; src[i] != '\0' && i < n; i++, ptr++)
    {
        *ptr = *(src + i);
    }

    for(; i < n; i++, ptr++)
    {
        *ptr = '\0';
    }

    return dst;
}

char *strdup(const char *s)
{
    size_t length = 0;
    char *dup = NULL;

    if(s == NULL)
    {
        return NULL;
    }

    length = strlen(s);
    dup = (char *)calloc(1, length + 1);
    if(dup == NULL)
    {
        return NULL;
    }

    strncpy(dup, s, length);

    return dup;
}

int strcmp(const char *s1, const char *s2)
{
    return strncmp(s1, s2, strlen(s2));
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    while(*s1 && *s2 && n)
    {
        if(*s1 > *s2)
        {
            return 1;
        }

        if(*s1 < *s2)
        {
            return -1;
        }

        s1++;
        s2++;
        n--;
    }

    if(n < 1)
    {
        return 0;
    }

    if(*s1)
    {
        return 1;
    }

    if(*s2)
    {
        return -1;
    }

    return 0;
}

char *strcat(char *dst, const char *src)
{
    char *ptr = dst;

    while(*ptr != '\0')
    {
        ptr++;
    }

    while(*src != '\0')
    {
        *ptr++ = *src++;
    }

    *ptr = '\0';

    return dst;
}

char *strncat(char *dst, const char *src, size_t n)
{
    char *ptr = dst;

    while(*ptr != '\0')
    {
        ptr++;
    }

    while(n > 0 && *src != '\0')
    {
        *ptr++ = *src++;
        n--;
    }

    *ptr = '\0';

    return dst;
}

char *strstr(const char *haystack, const char *needle)
{
    if(*needle == '\0')
    {
        return (char *)haystack;
    }

    while(*haystack)
    {
        const char *h = haystack;
        const char *n = needle;

        while(*h && *n && (*h == *n))
        {
            h++;
            n++;
        }

        if(*n == '\0')
        {
            return (char *)haystack;
        }

        haystack++;
    }

    return NULL;
}

char *strchr(const char *s, int c)
{
    while(*s)
    {
        if(*s == (char)c)
        {
            return (char *)s;
        }
        s++;
    }

    return NULL;
}

char *strtok(char *str, const char *delim, char **saved_ptr)
{
    char *start = NULL;

    if(str == NULL && *saved_ptr != NULL)
    {
        str = *saved_ptr;
    }else if(str == NULL && *saved_ptr == NULL)
    {
        *saved_ptr = NULL;
        return NULL;
    }

    while(*str != '\0' && strchr(delim, *str))
    {
        str++;
    }

    if(*str == '\0')
    {
        *saved_ptr = NULL;
        return NULL;
    }

    start = str;

    while(*str && !strchr(delim, *str))
    {
        str++;
    }

    if(*str)
    {
        *str = '\0';
        *saved_ptr = str + 1;
    }else
    {
        *saved_ptr = NULL;
    }

    return start;
}

long strtol(const char *str, int base)
{
    size_t i = 0;
    long val = 0;

    switch(base)
    {
        case 16:
            while(str[i] && i < MAX_STR_LEN)
            {
                char c = str[i++];

                if(c >= '0' && c <= '9')
                {
                    val *= 16;
                    val += c - '0';
                }else if(c >= 'A' && c <= 'F')
                {
                    val *= 16;
                    val += c - 'A' + 10;
                }else if(c >= 'a' && c <= 'f')
                {
                    val *= 16;
                    val += c - 'a' + 10;
                }else if(val)
                {
                    break;
                }
            }
            break;

        case 10:
            while(str[i] && i < MAX_STR_LEN)
            {
                char c = str[i++];

                if(c >= '0' && c <= '9')
                {
                    val *= 10;
                    val += c - '0';
                }else if(val)
                {
                    break;
                }
            }
            break;

        default:
            break;
    }

    return val;
}

wchar_t towlower(wchar_t wc)
{
    if(wc >= L'A' && wc <= L'Z')
    {
        return wc + (L'a' - L'A');
    }

    return wc;
}

int wcsicmp(const wchar_t *s1, const wchar_t *s2)
{
    wchar_t c1;
    wchar_t c2;

    while(*s1 && *s2)
    {
        c1 = towlower(*s1);
        c2 = towlower(*s2);

        if(c1 != c2)
        {
            return c1 - c2;
        }

        s1++;
        s2++;
    }

    return *s1 - *s2;
}

void charToWchar(const char* charStr, wchar_t* wcharStr, size_t wcharStrSize)
{
    size_t i = 0;

    for(i = 0; i < wcharStrSize - 1 && charStr[i] != '\0'; i++)
    {
        wcharStr[i] = (wchar_t)(unsigned char)charStr[i];
    }

    wcharStr[i] = L'\0';
}


void wcharToChar(const wchar_t* wstr, char* cstr, size_t cstrSize)
{
    size_t i = 0;

    for(i = 0; i < cstrSize - 1 && wstr[i] != L'\0'; i++)
    {
        if(wstr[i] < 0x80)
        {
            cstr[i] = (char)wstr[i];
        }else
        {
            cstr[i] = '?';
        }
    }
    cstr[i] = '\0';
}

int atoi(const char *nptr)
{
    int sign = 1;
    int val = 0;
    const char *pos = nptr;

    while(*pos == ' ')
    {
        pos++;
    }

    if(*pos == '-')
    {
        sign = -1;
        pos++;
    }else if(*pos == '+')
    {
        pos++;
    }

    while(*pos >= '0' && *pos <= '9')
    {
        val *= 10;
        val += *pos - '0';
        pos++;
    }

    return sign * val;
}

long atol(const char *nptr)
{
    long sign = 1;
    long val = 0;
    const char *pos = nptr;

    while(*pos == ' ')
    {
        pos++;
    }

    if(*pos == '-')
    {
        sign = -1;
        pos++;
    }else if(*pos == '+')
    {
        pos++;
    }

    while(*pos >= '0' && *pos <= '9')
    {
        val *= 10;
        val += *pos - '0';
        pos++;
    }

    return sign * val;
}

static void putstring(char *str)
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    size_t length = strlen(str);

    status = NtWriteFile(stdout, NULL, NULL, NULL, &ioStatusBlock, str, length, NULL, (PULONG)0);
}

static int putchar(char *str, char c)
{
    *str = c;

    return 1;
}

static int putint(char *str, char fill, int width, int value)
{
    int num = 0;
    unsigned int absolute;

    if(value < 0)
    {
        absolute = -value;
    }else
    {
        absolute = value;
    }

    width--;

    if((absolute / 10) > 0)
    {
        if(value < 0)
        {
            num = putint(str, fill, width, -(absolute / 10));
        }else
        {
            num = putint(str, fill, width, (absolute / 10));
        }
        str += num;
    }else
    {
        if(value < 0)
        {
            width--;
        }

        while(width > 0)
        {
            putchar(str, fill);
            str++;
            num++;
            width--;
        }

        if(value < 0)
        {
            num += putchar(str, '-');
            str++;
        }
    }

    num += putchar(str, (absolute % 10) + '0');

    return num;
}

static int putdouble(char *str, int width, double value)
{
    int num = 0;
    int i = 0;
    int e = 0;

    if(width < 1)
    {
        width = 11;
    }

    if(value < 0.0)
    {
        value = -value;
        num += putchar(str, '-');
        str++;
    }

    while(value < 1.0 && e > -310)
    {
        value *= 10;
        e--;
    }

    while(value > 10.0 && e < 310)
    {
        value /= 10;
        e++;
    }

    if(e >= 310 || e <= -310)
    {
        num += putchar(str, 'i');
        str++;
        num += putchar(str, 'n');
        str++;
        num += putchar(str, 'f');
        str++;

        return num;
    }

    if((int)value > 9)
    {
        num += putchar(str, 'n');
        str++;
        num += putchar(str, 'a');
        str++;
        num += putchar(str, 'n');
        str++;

        return num;
    }

    num += putchar(str, (int)value + '0');
    str++;
    num += putchar(str, '.');
    str++;

    for(i = 0; i < width; i++)
    {
        value -= (int)value;
        value *= 10;
        num += putchar(str, (int)value + '0');
        str++;
    }

    num += putchar(str, 'e');
    str++;
    num += putint(str, ' ', 0, e);

    return num;
}

static int putunsignedint(char *str, char fill, int width, unsigned int value)
{
    int num = 0;

    width--;

    if((value / 10) > 0)
    {
        num = putunsignedint(str, fill, width, (value / 10));
        str += num;
    }else
    {
        while(width > 0)
        {
            putchar(str, fill);
            str++;
            num++;
            width--;
        }
    }

    num += putchar(str, (value % 10) + '0');

    return num;
}

static int putunsignedlonglong(char *str, char fill, int width, unsigned long long value)
{
    int num = 0;

    width--;

    if((value / 10) > 0)
    {
        num = putunsignedlonglong(str, fill, width, (value / 10));
        str += num;
    }else
    {
        while(width > 0)
        {
            putchar(str, fill);
            str++;
            num++;
            width--;
        }
    }

    num += putchar(str, (value % 10) + '0');

    return num;
}

static int puthex(char *str, char fill, int width, unsigned char cap, unsigned long long value)
{
    int num = 0;

    width--;

    if((value >> 4) > 0)
    {
        num += puthex(str, fill, width, cap, (value >> 4));
        str += num;
    }else
    {
        while(width > 0)
        {
            putchar(str, fill);
            str++;
            num++;
            width--;
        }
    }

    if((value & 0xf) < 10)
    {
        putchar(str, (value & 0xf) + '0');
    }else if(cap)
    {
        putchar(str, (value & 0xf) - 10 + 'A');
    }else
    {
        putchar(str, (value & 0xf) - 10 + 'a');
    }

    num++;

    return num;
}

static int putstr(char *str, char fill, int width, const char *src)
{
    int num = 0;

    while(*src != 0)
    {
        *str++ = *src++;
        num++;
    }

    width -= num;

    while(width > 0)
    {
        *str++ = fill;
        num++;
        width--;
    }

    return num;
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    char fill = 0;
    size_t width = 0;
    size_t num = 0;
    size_t length = 0;

    if(str)
    {
        *str = '\0';
    }

    while(*format != 0 && length < size)
    {
        if(*format != '%')
        {
            *str++ = *format++;
            length++;
        }else if(*(format + 1) == '%')
        {
            *str++ = '%';
            format += 2;
            length++;
        }else{
            fill = ' ';
            width = 0;
            format++;

            if(*format == '0')
            {
                fill = '0';
                format++;
            }

            if(*format == '-')
            {
                format++;
            }

            while(*format >= '0' && *format <= '9')
            {
                width = width * 10 + *format - '0';
                format++;
            }

            if(length + width > size)
            {
                width = size - length;
            }

            switch(*format)
            {
                case 'd':
                case 'i':
                    num = putint(str, fill, width, va_arg(ap, int));
                    break;

                case 'f':
                    num = putdouble(str, width, va_arg(ap, double));
                    break;

                case 'p':
                    num = puthex(str, '0', 2 * sizeof(unsigned long long), 0, va_arg(ap, unsigned long long));
                    break;

                case 'u':
                    num = putunsignedint(str, fill, width, va_arg(ap, unsigned int));
                    break;

                case 'l':
                    num = putunsignedlonglong(str, fill, width, va_arg(ap, unsigned long long));
                    break;

                case 'x':
                    num = puthex(str, fill, width, 0, va_arg(ap, unsigned long long));
                    break;

                case 'X':
                    num = puthex(str, fill, width, 1, va_arg(ap, unsigned long long));
                    break;

                case 's':
                    num = putstr(str, fill, width, va_arg(ap, char *));
                    break;

                case 'c':
                    num = putchar(str, va_arg(ap, int));
                    break;

                default:
                    return -1;
            }

            format++;
            str += num;
            length += num;
        }
    }

    if(length < size)
    {
        *str = '\0';
    }else
    {
        *(--str) = '\0';
        length--;
    }

    return length;
}

int sprintf(char *str, const char *format, ...)
{
    va_list ap;
    size_t result = 0;

    va_start(ap, format);
    result = vsnprintf(str, MAX_PRINT_STR_LEN, format, ap);
    va_end(ap);

    return result;
}

int snprintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    size_t result = 0;

    va_start(ap, format);
    result = vsnprintf(str, size, format, ap);
    va_end(ap);

    return result;
}

void printf(const char *format, ...)
{
    char buffer[MAX_PRINT_STR_LEN] = {0};
    va_list ap;
    size_t result = 0;

    va_start(ap, format);
    result = vsnprintf(buffer, MAX_PRINT_STR_LEN, format, ap);
    va_end(ap);

    putstring(buffer);
}

char *fgets(HANDLE handle, char *s, int size)
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    int count = 0;
    char ch;

    while(count < size -1)
    {
        status = NtReadFile(handle, NULL, NULL, NULL, &ioStatusBlock, &ch, 1, NULL, (PULONG)0);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("fgets error: %x\n", status);
#endif
            return NULL;
        }

        if(ch == 0xd)
        {
            continue;
        }

        if(ch == '\n')
        {
            break;
        }

        s[count++] = ch;
    }

    s[count] = '\0';

    return (count > 0) ? s : NULL;
}

uint16_t htons(uint16_t hostshort)
{
    return (hostshort << 8) | (hostshort >> 8);
}

uint32_t htonl(uint32_t hostlong)
{
    return (hostlong << 24) | ((hostlong & 0x00FF0000) >> 8) | ((hostlong & 0x0000FF00) << 8) | (hostlong >> 24);
}

uint64_t htonll(uint64_t hostlonglong)
{
    return ((1 == htonl(1)) ? (hostlonglong) : (((uint64_t)htonl((hostlonglong) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((hostlonglong) >> 32)));
}

uint16_t ntohs(uint16_t netshort)
{
    return htons(netshort);
}

uint32_t ntohl(uint32_t netlong)
{
    return htonl(netlong);
}

uint64_t ntohll(uint64_t netlonglong)
{
    return ((1 == ntohl(1)) ? (netlonglong) : (((uint64_t)ntohl((netlonglong) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((netlonglong) >> 32)));
}

in_addr_t inet_addr(const char *cp)
{
    in_addr addr;
    unsigned int bytes[4];
    int byte_count = 0;

    while(*cp)
    {
        if(*cp >= '0' && *cp <= '9')
        {
            int value = 0;

            while(*cp >= '0' && *cp <= '9')
            {
                value = value * 10 + (*cp - '0');
                cp++;
            }

            if(value > 255)
            {
                goto error;
            }

            bytes[byte_count++] = value;

            if(*cp == '.')
            {
                cp++;
            }
        }else
        {
            goto error;
        }

        if(byte_count > 4)
        {
            goto error;
        }
    }

    addr.s_addr = (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];

    return addr.s_addr;

    error:
    addr.s_addr = 0;

    return addr.s_addr;
}

char *inet_ntoa(in_addr in)
{
    char *buffer = (char *)calloc(16, sizeof(char));

    sprintf(buffer, "%u.%u.%u.%u", (in.s_addr & 0x000000FF), (in.s_addr & 0x0000FF00) >> 8, (in.s_addr & 0x00FF0000) >> 16, (in.s_addr & 0xFF000000) >> 24);

    return buffer;
}

int inet_pton(int af, const char *src, void *dst)
{
    unsigned int bytes[4];
    int byte_count = 0;
    unsigned int segments[8];
    int segment_count = 0;
    const char *pos = NULL;
    int double_colon_start_segment_index = -1;
    int double_colon_end_segment_index = -1;
    int value = 0;
    char ch;
    int i = 0;

    if(af == AF_INET)
    {
        while(*src != '\0')
        {
            ch = *src;

            if(ch >= '0' && ch <= '9')
            {
                value = value * 10 + ch - '0';
            }else if(ch == '.')
            {
                if(byte_count >= 3 || value > 255)
                {
                    return 0;
                }

                bytes[byte_count++] = value;
                value = 0;
            }else
            {
                return 0;
            }

            src++;
        }

        if(byte_count == 3 && value <= 255)
        {
            bytes[byte_count++] = value;
        }

        if(byte_count != 4)
        {
            return 0;
        }

        ((in_addr *)dst)->s_addr = (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];
    }else if(af == AF_INET6)
    {
        pos = src;

        if(*pos == ':') // ::1
        {
            double_colon_start_segment_index = 0;
        }

        while(*pos != '\0')
        {
            ch = *pos;

            if((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))
            {
                pos++;
            }else if(ch == ':')
            {
                if(segment_count >= 8)
                {
                    return 0;
                }

                segment_count++;
                pos++;

                if(*pos == ':')  // ::
                {
                    if(double_colon_start_segment_index > 0)
                    {
                        return 0;
                    }else if(double_colon_start_segment_index == -1)
                    {
                        double_colon_start_segment_index = segment_count;
                        segment_count = 0;
                    }

                    pos++;
                }
            }else
            {
                return 0;
            }
        }

        if(double_colon_start_segment_index == 0)   // ::1
        {
            double_colon_end_segment_index = 7 - segment_count;
        }else if(double_colon_start_segment_index != -1)
        {
            double_colon_end_segment_index = 7 - segment_count - 1;
        }

        pos = src;
        segment_count = 0;

        if(double_colon_start_segment_index == 0)   // ::1
        {
            while(segment_count <= double_colon_end_segment_index)
            {
                segments[segment_count++] = 0;
            }

            pos++;  // :
            pos++;  // :

            while(*pos != '\0')
            {
                ch = *pos;

                if((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))
                {
                    if(value > 0xFFFF)
                    {
                        return 0;
                    }

                    value = value * 16 + ((ch >= '0' && ch <= '9') ? (ch - '0') : (ch >= 'a' ? (ch - 'a' + 10) : (ch - 'A' + 10)));
                }else if(ch == ':')
                {
                    if(segment_count >= 8)
                    {
                        return 0;
                    }

                    segments[segment_count++] = value;
                    value = 0;
                }else
                {
                    return 0;
                }

                pos++;
            }

            if(segment_count < 8)
            {
                segments[segment_count] = value;
            }
        }else
        {
            while(*pos != '\0')
            {
                ch = *pos;

                if((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))
                {
                    if(value > 0xFFFF)
                    {
                        return 0;
                    }

                    value = value * 16 + ((ch >= '0' && ch <= '9') ? (ch - '0') : (ch >= 'a' ? (ch - 'a' + 10) : (ch - 'A' + 10)));
                }else if(ch == ':')
                {
                    if(segment_count >= 8)
                    {
                        return 0;
                    }

                    segments[segment_count++] = value;
                    value = 0;

                    if(*(pos + 1) == ':')
                    {
                        if(segment_count == double_colon_start_segment_index)
                        {
                            while(segment_count <= double_colon_end_segment_index)
                            {
                                segments[segment_count++] = 0;
                            }
                        }

                        pos++;
                    }
                }else
                {
                    return 0;
                }

                pos++;
            }
        }

        if(segment_count < 8)
        {
            segments[segment_count] = value;
        }

        for(i = 0; i < 8; i++)
        {
            ((in6_addr *)dst)->s6_addr[i * 2] = (segments[i] >> 8) & 0xFF;
            ((in6_addr *)dst)->s6_addr[i * 2 + 1] = segments[i] & 0xFF;
        }
    }else
    {
        return 0;
    }

    return 1;
}

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
    in_addr_t s_addr = *(long *)src;
    const uint16_t *addr = (const uint16_t *)src;
    int longest_zero_idx = -1;
    int longest_zero_len = 0;
    int current_zero_len = 0;
    int i = 0;
    int seq_length = 0;
    char *ptr = dst;
    int skip = 0;

    if(af == AF_INET && size >= 16)
    {
        sprintf(dst, "%u.%u.%u.%u", (s_addr & 0x000000FF), (s_addr & 0x0000FF00) >> 8, (s_addr & 0x00FF0000) >> 16, (s_addr & 0xFF000000) >> 24);
    }else if(af == AF_INET6 && size >= INET6_ADDR_STRING_LENGTH)
    {
        if(addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 && addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0)
        {
            return 0;
        }

        for(i = 0; i < 8; i++)
        {
            if(addr[i] == 0)
            {
                if(current_zero_len == 0)
                {
                    current_zero_len = 1;
                    longest_zero_idx = i;
                }else
                {
                    current_zero_len++;
                }
            }else
            {
                if(current_zero_len > longest_zero_len)
                {
                    longest_zero_len = current_zero_len;
                }

                current_zero_len = 0;
            }
        }

        if(current_zero_len > longest_zero_len)
        {
            longest_zero_len = current_zero_len;
            longest_zero_idx = 8 - current_zero_len;
        }

        for(i = 0; i < 8; i++)
        {
            if(i == longest_zero_idx)
            {
                *ptr++ = ':';

                if(longest_zero_len > 1)
                {
                    i += longest_zero_len -1;

                    continue;
                }else
                {
                    skip = 1;
                }
            }

            ptr += sprintf(ptr, "%x", ntohs(addr[i]));

            if(i < 7)
            {
                *ptr++ = ':';
            }
        }

        *ptr = '\0';
    }else
    {
        return NULL;
    }

    return dst;
}

static int is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

static int days_in_month(int month, int year)
{
    const int days_in_months[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    if(month == 1 && is_leap_year(year))
    {
        return 29;
    }

    return days_in_months[month];
}

char *ctime(const time_t *timep)
{
    static char buffer[MAX_PRINT_STR_LEN] = {0};
    struct tm time_info;
    const char* week_days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const char* month_names[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    time_info.tm_sec = *timep % 60;
    int total_minutes = *timep / 60;
    time_info.tm_min = total_minutes % 60;
    int total_hours = total_minutes / 60;
    time_info.tm_hour = total_hours % 24;

    long total_days = total_hours / 24;
    time_info.tm_year = 1970;

    while(total_days >= 365)
    {
        total_days -= (is_leap_year(time_info.tm_year) ? 366 : 365);
        time_info.tm_year++;
    }

    time_info.tm_yday = total_days;

    int month = 0;
    while(total_days >= days_in_month(month, time_info.tm_year))
    {
        total_days -= days_in_month(month, time_info.tm_year);
        month++;
    }

    time_info.tm_mon = month;
    time_info.tm_mday = total_days + 1;
    time_info.tm_wday = (total_days + 4) % 7;

    sprintf(buffer, "%s %s %d %02d:%02d:%02d %d", week_days[time_info.tm_wday], month_names[time_info.tm_mon], time_info.tm_mday, time_info.tm_hour, time_info.tm_min, time_info.tm_sec, time_info.tm_year);

    return buffer;
}

int gettimeofday(timeval *tv, timezone *tz)
{
    LARGE_INTEGER systemTime;

    NTSTATUS status = NtQuerySystemTime(&systemTime);
    if(!NT_SUCCESS(status))
    {
        return -1;
    }

    const int64_t UnixEpoch = 116444736000000000LL;
    int64_t timeInUs = (systemTime.QuadPart - UnixEpoch) / 10;

    tv->tv_sec = timeInUs / 1000000;
    tv->tv_usec = timeInUs % 1000000;

    return 0;
}

unsigned short *GetCommandLineW()
{
    void *cmd = NULL;

    __asm__ __volatile__
    (
        "movq %%gs:(0x60), %[cmd]\n"
        "movq 0x20(%[cmd]), %[cmd]\n"
        "movq 0x78(%[cmd]), %[cmd]\n"
        : [cmd] "=r" (cmd)
    );

    return cmd;
}

int CmdlineToArgv(const unsigned short *cmd, char **argv)
{
    int argc = 1;
    int state = 6;
    int slash = 0;
    int c = 0;
    char *buffer = (char *)(argv + 16384);

    argv[0] = buffer;

    while(*cmd)
    {
        c = *cmd++;
        if(((c >> 10) == 0x36) && ((*cmd >> 10) == 0x37))
        {
            c = 0x10000 + ((c - 0xd800) << 10) + (*cmd++ - 0xdc00);
        }

        switch(state)
        {
            case 0:
                if(c == 0x09 || c == 0x20)
                {
                    continue;
                }else if(c == 0x22)
                {
                    argv[argc++] = buffer;
                    state = 2;
                    continue;
                }else if(c == 0x5c)
                {
                    argv[argc++] = buffer;
                    slash = 1;
                    state = 3;
                }else
                {
                    argv[argc++] = buffer;
                    state = 1;
                }
                break;
            case 1:
                if(c == 0x09 || c == 0x20)
                {
                    *buffer++ = 0;
                    state = 0;
                    continue;
                }else if(c == 0x22)
                {
                    state = 2;
                    continue;
                }else if(c == 0x5c)
                {
                    slash = 1;
                    state = 3;
                }
                break;
            case 2:
                if(c == 0x22)
                {
                    state = 5;
                    continue;
                }else if(c == 0x5c)
                {
                    slash = 1;
                    state = 4;
                }
                break;
            case 3:
            case 4:
                if(c == 0x22)
                {
                    buffer -= ((1 + slash) >> 1);

                    if(slash & 1)
                    {
                        state -= 2;
                        break;
                    }

                    cmd -= 1 + (c >= 0x10000);
                    state -= 2;
                    continue;
                }else if(c == 0x5c)
                {
                    slash++;
                }else
                {
                    cmd -= 1 + (c >= 0x10000);
                    state -= 2;
                    continue;
                }

                break;
            case 5:
                if(c == 0x22)
                {
                    state = 1;
                }else
                {
                    cmd -= 1 + (c >= 0x10000);
                    state = 1;
                    continue;
                }

                break;
            case 6:
                if(c == 0x09 || c == 0x20)
                {
                    *buffer++ = 0;
                    state = 0;
                    continue;
                }else if(c == 0x22)
                {
                    state = 8;
                    continue;
                }else
                {
                    state = 7;
                }

                break;
            case 7:
                if(c == 0x09 || c == 0x20)
                {
                    *buffer++ = 0;
                    state = 0;
                    continue;
                }

                break;
            case 8:
                if(c == 0x22)
                {
                    *buffer++ = 0;
                    state = 0;
                    continue;
                }

                break;
        }

        switch((c >= 0x80) + (c >= 0x800) + (c >= 0x10000))
        {
            case 0:
                *buffer++ = 0x00 | c;
                break;
            case 1:
                *buffer++ = 0xc0 | ((c >> 6));
                *buffer++ = 0x80 | (c & 63);
                break;
            case 2:
                *buffer++ = 0xe0 | ((c >> 12));
                *buffer++ = 0x80 | ((c >> 6) & 63);
                *buffer++ = 0x80 | (c & 63);
                break;
            case 3:
                *buffer++ = 0xf0 | ((c >> 18));
                *buffer++ = 0x80 | ((c >> 12) & 63);
                *buffer++ = 0x80 | ((c >> 6) & 63);
                *buffer++ = 0x80 | (c & 63);
                break;
        }
    }

    *buffer = 0;
    argv[argc] = 0;

    return argc;
}

VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
    if(DestinationString != NULL)
    {
        if(SourceString != NULL)
        {
            DestinationString->Length = (USHORT)(wcslen(SourceString) * 2);
            DestinationString->MaximumLength = (USHORT)(DestinationString->Length + 2);
            DestinationString->Buffer = (PWSTR)SourceString;
        }else
        {
            DestinationString->Length = 0;
            DestinationString->MaximumLength = 0;
            DestinationString->Buffer = NULL;
        }
    }
}

VOID InitializeObjectAttributes(POBJECT_ATTRIBUTES p, HANDLE r, PUNICODE_STRING n, ULONG a, PSECURITY_DESCRIPTOR s, PSECURITY_QUALITY_OF_SERVICE sq)
{
    if(p != NULL)
    {
        p->Length = sizeof(OBJECT_ATTRIBUTES);
        p->RootDirectory = r;
        p->ObjectName = n;
        p->Attributes = a;
        p->SecurityDescriptor = s;
        p->SecurityQualityOfService = sq;
    }
}

HANDLE GetStdHandle(DWORD nStdHandle)
{
    HANDLE hFile = NULL;
    SECURITY_QUALITY_OF_SERVICE security_quality_of_service;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    UNICODE_STRING deviceName;
    NTSTATUS status;

    switch(nStdHandle)
    {
        case STD_INPUT_HANDLE:
            RtlInitUnicodeString(&deviceName, L"\\??\\CONIN$");
            break;

        case STD_OUTPUT_HANDLE:
            RtlInitUnicodeString(&deviceName, L"\\??\\CONOUT$");
            break;

        case STD_ERROR_HANDLE:
            RtlInitUnicodeString(&deviceName, L"\\??\\CONOUT$");
            break;

        default:
            return INVALID_HANDLE_VALUE;
    }

    security_quality_of_service.Length = 0xc;
    security_quality_of_service.ImpersonationLevel = 2;
    security_quality_of_service.ContextTrackingMode = 1;
    security_quality_of_service.EffectiveOnly = 1;

    InitializeObjectAttributes(&objectAttributes, NULL, &deviceName, 0x40, NULL, &security_quality_of_service);

    if(nStdHandle == STD_INPUT_HANDLE)
    {
        status = NtCreateFile(&hFile,
                              GENERIC_READ | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
                              &objectAttributes,
                              &ioStatusBlock,
                              NULL,
                              0,
                              0,
                              0x1,
                              0x60,
                              NULL,
                              0);
    }else
    {
        status = NtCreateFile(&hFile,
                              GENERIC_WRITE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
                              &objectAttributes,
                              &ioStatusBlock,
                              NULL,
                              0,
                              0,
                              0x1,
                              0x60,
                              NULL,
                              0);
    }

    if(!NT_SUCCESS(status))
    {
        return INVALID_HANDLE_VALUE;
    }

    return hFile;
}

void *GetPeb()
{
    void *ptr = NULL;

    __asm__ __volatile__
    (
        "movq %%gs:(0x60), %[ptr]\n"
        : [ptr] "=r" (ptr)
    );

    return ptr;
}

ULONG GetSessionId()
{
    PEB64 *peb = (PEB64 *)GetPeb();
    ULONG sessionId = peb->SessionId;

    return sessionId;
}

NTSTATUS BaseGetNamedObjectDirectory(HANDLE *dir)
{
    NTSTATUS status = 0;
    HANDLE handle;
    CHAR tmp[64] = {0};
    WCHAR buffer[64] = {0};
    UNICODE_STRING str;
    OBJECT_ATTRIBUTES objectAttributes;
    ULONG sessionId = GetSessionId();

    snprintf(tmp, 64, "\\Sessions\\%u\\BaseNamedObjects", sessionId);
    charToWchar(tmp, buffer, 64);
    RtlInitUnicodeString(&str, buffer);
    InitializeObjectAttributes(&objectAttributes, NULL, &str, 0, NULL, NULL);
    status = NtOpenDirectoryObject(&handle, DIRECTORY_CREATE_OBJECT | DIRECTORY_TRAVERSE, &objectAttributes);
    if(!NT_SUCCESS(status))
    {
        NtClose(handle);
    }

    *dir = handle;

    return status;
}

HMODULE GetModuleHandleW(wchar_t *lpModuleName)
{
    PEB64 *peb = (PEB64 *)GetPeb();
    PPEB_LDR_DATA Ldr = NULL;
    PLIST_ENTRY ModuleList = NULL;
    PLIST_ENTRY StartListEntry = NULL;
    PLIST_ENTRY ListEntry = NULL;
    PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = NULL;

    if(lpModuleName == NULL)
    {
        return (HMODULE)(peb->ImageBaseAddress);
    }

    Ldr = (PPEB_LDR_DATA)peb->Ldr;
    ModuleList = (PLIST_ENTRY)&Ldr->InMemoryOrderModuleList;
    StartListEntry = (PLIST_ENTRY)ModuleList->Flink;

    for(ListEntry = StartListEntry; ListEntry != ModuleList; ListEntry = (PLIST_ENTRY)ListEntry->Flink)
    {
        LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ListEntry - sizeof(LIST_ENTRY));

        if(wcsicmp((wchar_t *)LdrDataTableEntry->BaseDllName.Buffer, lpModuleName) == 0){
            return (HMODULE)LdrDataTableEntry->DllBase;
        }
    }

    return NULL;
}

FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    HMODULE BaseAddress = hModule;
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
    PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)BaseAddress + DosHeader->e_lfanew);
    PIMAGE_FILE_HEADER FileHeader = (PIMAGE_FILE_HEADER)&NtHeaders->FileHeader;
    PIMAGE_OPTIONAL_HEADER64 OptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&NtHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER SectionHeader = NULL;
    PVOID rdataAddress = 0;
    SIZE_T rdataSize = 0;
    int i = 0;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    DWORD numberOfNames = 0;
    DWORD *AddressOfNames = NULL;
    WORD *AddressOfNameOrdinals = NULL;
    DWORD *AddressOfFunctions = NULL;
    _LoadLibraryA LoadLibraryA = NULL;
    LPSTR functionName = NULL;
    WORD ordinal = 0;
    DWORD base = 0;
    DWORD rva = 0;
    char *forwarder = NULL;
    char tmp[256] = {0};
    char *token = NULL;
    char dname[256] = {0};
    char *fname = NULL;
    FARPROC FunctionAddress = NULL;
    DWORD j = 0;
    char *saved_ptr = NULL;

    if(NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    {
        return NULL;
    }

    for(i = 0; i < FileHeader->NumberOfSections; i++)
    {
        SectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)BaseAddress + DosHeader->e_lfanew + sizeof(PIMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER)));

        if(strncmp((char *)SectionHeader->Name, ".rdata", strlen(".rdata")) == 0)
        {
            rdataAddress = (PVOID)((LPBYTE)BaseAddress + SectionHeader->VirtualAddress);
            rdataSize = SectionHeader->Misc.VirtualSize;
        }
    }


    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseAddress + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    numberOfNames = ExportDirectory->NumberOfNames;
    AddressOfNames = (DWORD *)((LPBYTE)BaseAddress + ExportDirectory->AddressOfNames);
    AddressOfNameOrdinals = (WORD *)((LPBYTE)BaseAddress + ExportDirectory->AddressOfNameOrdinals);
    AddressOfFunctions = (DWORD *)((LPBYTE)BaseAddress + ExportDirectory->AddressOfFunctions);

    if(((ULONGLONG)lpProcName >> 16) == 0)
    {
        ordinal = (WORD)((ULONGLONG)lpProcName & 0xFFFF);
        base = ExportDirectory->Base;
        rva = AddressOfFunctions[ordinal - base];

        if(ordinal < base || ordinal >= base + ExportDirectory->NumberOfFunctions)
        {
            return NULL;
        }

        FunctionAddress = (FARPROC)((LPBYTE)BaseAddress + rva);

        return FunctionAddress;
    }else
    {
        for(j = 0; j < numberOfNames; j++)
        {
            functionName = (LPSTR)((LPBYTE)BaseAddress + AddressOfNames[j]);
            ordinal = AddressOfNameOrdinals[j];
            rva = AddressOfFunctions[ordinal];

            if(strncmp(functionName, lpProcName, strlen(lpProcName)) == 0)
            {
                forwarder = (char *)((LPBYTE)BaseAddress + rva);

                if((PVOID)forwarder >= rdataAddress && (PVOID)forwarder <= rdataAddress + rdataSize)
                {
                    if(strstr(forwarder, ".") != NULL)
                    {
                        memcpy(tmp, forwarder, strlen(forwarder));
                        token = strtok(tmp, ".", &saved_ptr);
                        sprintf(dname, "%s.dll", token);

                        while(token != NULL)
                        {
                            token = strtok(NULL, ".", &saved_ptr);
                            if(token != NULL)
                            {
                                fname = token;
                            }
                        }

                        LoadLibraryA = GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "LoadLibraryA");
                        if(LoadLibraryA != NULL)
                        {
                            FunctionAddress = GetProcAddress(LoadLibraryA(dname), fname);
                        }else
                        {
                            return NULL;
                        }

                        if(FunctionAddress != NULL)
                        {
                            return FunctionAddress;
                        }else
                        {
                            FunctionAddress = (FARPROC)((LPBYTE)BaseAddress + rva);

                            return FunctionAddress;
                        }
                    }else
                    {

                        FunctionAddress = (FARPROC)((LPBYTE)BaseAddress + rva);

                        return FunctionAddress;
                    }
                }else
                {
                    FunctionAddress = (FARPROC)((LPBYTE)BaseAddress + rva);

                    return FunctionAddress;
                }
            }
        }
    }

    return NULL;
}

void *search_syscall_address(char *name)
{
    HMODULE BaseAddress = NULL;
    PIMAGE_DOS_HEADER DosHeader = NULL;
    PIMAGE_NT_HEADERS64 NtHeaders = NULL;
    PIMAGE_FILE_HEADER FileHeader = NULL;
    PIMAGE_OPTIONAL_HEADER64 OptionalHeader = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PIMAGE_SECTION_HEADER SectionHeader = NULL;
    WORD numberOfSections = 0;

    DWORD ordinalBase = 0;
    DWORD numberOfFunctions = 0;
    DWORD numberOfNames = 0;
    DWORD d = 0;
    PDWORD AddressOfFunctions = NULL;
    PDWORD AddressOfNames = NULL;
    PWORD AddressOfNameOrdinals = NULL;
    DWORD i = 0;
    PCHAR FunctionName = NULL;
    PBYTE FunctionAddress = NULL;
    WORD ordinal = 0;

    BaseAddress = GetModuleHandleW(L"NTDLL.DLL");
    if(BaseAddress == NULL)
    {
        return NULL;
    }

    DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
    NtHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)BaseAddress + DosHeader->e_lfanew);
    FileHeader = (PIMAGE_FILE_HEADER)&NtHeaders->FileHeader;
    OptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&NtHeaders->OptionalHeader;
    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)DosHeader + OptionalHeader->DataDirectory[0].VirtualAddress);

    ordinalBase = (DWORD)ExportDirectory->Base;
    numberOfFunctions = (DWORD)ExportDirectory->NumberOfFunctions;
    numberOfNames = (DWORD)ExportDirectory->NumberOfNames;

    d = numberOfFunctions - numberOfNames;
    if(d < 0)
    {
        d = 0;
    }

    AddressOfFunctions = (PDWORD)((PBYTE)BaseAddress + ExportDirectory->AddressOfFunctions);
    AddressOfNames = (PDWORD)((PBYTE)BaseAddress + ExportDirectory->AddressOfNames);
    AddressOfNameOrdinals = (PWORD)((PBYTE)BaseAddress + ExportDirectory->AddressOfNameOrdinals);

    for(i = 0; i < numberOfNames; i++)
    {
        FunctionName = (PCHAR)((PBYTE)BaseAddress + AddressOfNames[i]);
        FunctionAddress = (PBYTE)((PBYTE)BaseAddress + AddressOfFunctions[i + d]);
        ordinal = (WORD)ordinalBase + AddressOfNameOrdinals[i];

        if(strcmp(name, (char *)FunctionName) == 0)
        {
            if(*((PBYTE)FunctionAddress + 0x12) == 0x0f && *((PBYTE)FunctionAddress + 0x13) == 0x05 && *((PBYTE)FunctionAddress + 0x14) == 0xc3) // 0x0f05:syscall 0xc3:ret
            {
#ifdef _DEBUG
//                printf("[+] search_syscall_address syscall: %x\n", (PBYTE)FunctionAddress + 0x12);
#endif
                return (void *)FunctionAddress + 0x12;
            }else
            {
                return NULL;
            }
        }
    }

    return NULL;
}


// spider function
char hex_char_to_int(char c)
{
    if((c >= '0') && (c <= '9'))
    {
        c = c - '0';
    }else if((c >= 'a') && (c <= 'f'))
    {
        c = c + 10 - 'a';
    }else if((c >= 'A') && (c <= 'F'))
    {
        c = c + 10 - 'A';
    }else
    {
        c = 0;
    }
    return c;
}

void hex_string_to_array(const char *hex_string, int32_t hex_string_length, unsigned char *buffer, int32_t buffer_size)
{
    char tmp1 = 0;
    char tmp2 = 0;
    int32_t length = 0;
    int32_t i = 0;

    for(i = 0; i < hex_string_length && length < buffer_size; i += 2)
    {
        tmp1 = hex_char_to_int(hex_string[i]);
        tmp2 = hex_char_to_int(hex_string[i + 1]);

        tmp1 = tmp1 << 4;
        buffer[length] = (unsigned char)(tmp1 + tmp2);
        length++;
    }
}

void print_bytes(char *buffer, int buffer_length)
{
    for(int i = 0; i < buffer_length; i++){
        if(i != 0 && i % 16 == 0){
            printf("\n");
        }else if(i % 16 == 8){
            printf(" ");
        }
        printf("%02x ", buffer[i] & 0xff);
    }
    printf("\n");

    return;
}

uint32_t generate_random_id()
{
    NTSTATUS status;
    LARGE_INTEGER performanceCounter;
    LARGE_INTEGER performanceFrequency;
    uint32_t id = 0;

    do{
        status = NtQueryPerformanceCounter(&performanceCounter, &performanceFrequency);
        id = (uint32_t)(performanceCounter.QuadPart ^ (performanceCounter.QuadPart >> 32));
    }while(id == 0);

    return id;
}

int32_t recv_data(SOCKET sock, char *buffer, int32_t buffer_size, long long tv_sec, long long tv_usec)
{
    int ret = 0;
    int32_t rec = 0;
    int32_t err = 0;
    struct fd_set readfds;
    struct timeval tv;

    memset((char *)buffer, 0, buffer_size);

    while(1)
    {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;

        ret = select(0, &readfds, NULL, NULL, &tv);
        if(ret == 0)
        {
#ifdef _DEBUG
            printf("[-] recv_data select timeout\n");
#endif

            return -1;
        }

        ret = FD_ISSET(sock, &readfds);
        if(ret > 0)
        {
            rec = recv(sock, buffer, buffer_size, 0);
            if(rec == SOCKET_ERROR)
            {
                err = WSAGetLastError();
                if(err == WSAEWOULDBLOCK)
                {
                    millisleep(5);
                    continue;
                }
#ifdef _DEBUG
                printf("[-] recv_data recv error: %d\n", err);
#endif

                return -1;
            }else
            {
                break;
            }
        }
    }

    return rec;
}

int32_t send_data(SOCKET sock, char *buffer, int32_t buffer_length, long long tv_sec, long long tv_usec)
{
    int ret = 0;
    int32_t sen = 0;
    int32_t err = 0;
    int32_t send_length = 0;
    int32_t len = 0;
    struct fd_set writefds;
    struct timeval tv;

    len = buffer_length;

    while(len > 0)
    {
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;

        ret = select(0, NULL, &writefds, NULL, &tv);
        if(ret == 0)
        {
#ifdef _DEBUG
            printf("[-] send_data select timeout\n");
#endif

            return -1;
        }

        ret = FD_ISSET(sock, &writefds);
        if(ret > 0)
        {
            sen = send(sock, buffer + send_length, len, 0);
            if(sen == SOCKET_ERROR)
            {
                err = WSAGetLastError();
                if(err == WSAEWOULDBLOCK)
                {
                    millisleep(5);
                    continue;
                }
#ifdef _DEBUG
                printf("[-] send_data send error: %d\n", err);
#endif

                return -1;
            }
            send_length += sen;
            len -= sen;
        }
    }

    return buffer_length;
}

