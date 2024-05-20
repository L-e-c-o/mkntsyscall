# mkntsyscall

Just a other fork of **mkwinsyscall**, a tool that generates windows system call bodies based on their prototypes.

The official documentation can be found there: https://pkg.go.dev/golang.org/x/sys/windows/mkwinsyscall

## Why this fork ?

I made this fork to generate system call bodies for the **ntsyscall** librarie, which allows you to make indirect syscalls. 
Additionally it allows you to resolve module handles (GetModuleHandle) and function (or proc) addresses (GetProcAddress) manually, without using the Windows API. It includes the API hashing technique (using fnv1a hashing algo) to hide which functions are used.

## Usage

This is a drop-in replacement of **mkwinsyscall**, so you just need to replace the URL from the `go generate` command.

For example: 

```go
//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output winsyscalls_windows.go definitions.go

//sys RtlCopyMemory(dest uintptr, src uintptr, dwSize uint32) = ntdll.RtlCopyMemory
//sys HeapAlloc(hHeap windows.Handle, dwFlags uint32, dwBytes uintptr) (lpMem uintptr, err error) = kernel32.HeapAlloc
```

Become:

```go
//go:generate go run mkntsyscall.go -output ntsyscalls_windows.go definitions.go

//sys NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, AllocationType uint32, protect uint32) (ntStatus uint32) = ntdll.NtAllocateVirtualMemory
```

## Output

The below example shows the output of the functions resolved using **ntsyscall** by hash.

```go
import (
	"unsafe"

	"ntsyscall"
)

func NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, AllocationType uint32, protect uint32) (ntStatus uint32) {
	return ntsyscall.Syscalls[0x54c4fa4].Call(uintptr(processHandle), uintptr(unsafe.Pointer(baseAddress)), uintptr(zeroBits), uintptr(unsafe.Pointer(regionSize)), uintptr(AllocationType), uintptr(protect))
}
```
