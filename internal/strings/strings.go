package strings

import (
	"unsafe"

	"github.com/malt3/purego-cryptsetup/internal/dlopen/libc"
)

// TODO: really, really test and think about this...

// CString converts a go string to *byte that can be passed to C code.
// This effectively creates a copy of the string.
// The caller is responsible for calling CFree on the returned pointer when done.
func CString(name string) *byte {
	buf := libc.Malloc(uint64(len(name) + 1))
	if buf == nil {
		return nil
	}
	// TODO: think about using memcpy / strncpy here
	for i := 0; i < len(name); i++ {
		*(*byte)(unsafe.Pointer(uintptr(buf) + uintptr(i))) = name[i]
	}
	*(*byte)(unsafe.Pointer(uintptr(buf) + uintptr(len(name)))) = 0

	return (*byte)(buf)
}

// CFree frees a pointer allocated by CString.
func CFree(ptr *byte) {
	libc.Free(unsafe.Pointer(ptr))
}

func PtrFree(ptr unsafe.Pointer) {
	libc.Free(ptr)
}

func Free[T any](ptr *T) {
	libc.Free(unsafe.Pointer(ptr))
}

func GoString(name *byte) string {
	if name == nil {
		return ""
	}
	l := libc.Strlen(name)
	buf := make([]byte, l)
	libc.Memcpy(unsafe.Pointer(&buf[0]), unsafe.Pointer(name), l)
	return string(buf)
}

func GoBytes(name *byte, size uint64) []byte {
	buf := make([]byte, size)
	libc.Memcpy(unsafe.Pointer(&buf[0]), unsafe.Pointer(name), size)
	return buf
}
