package libc

import "unsafe"

func Malloc(size uint64) unsafe.Pointer {
	return malloc_dl(size)
}

func Free(ptr unsafe.Pointer) {
	free_dl(ptr)
}

func Memcpy(dst, src unsafe.Pointer, size uint64) {
	memcpy_dl(dst, src, size)
}

func Strlen(s *byte) uint64 {
	return strlen_dl(s)
}

func Strncpy(dst, src *byte, size uint64) {
	strncpy_dl(dst, src, size)
}
