package libc

import "unsafe"

var (
	malloc_dl  malloc
	free_dl    free
	memcpy_dl  memcpy
	strlen_dl  strlen
	strncpy_dl strncpy
)

type malloc func(size uint64) unsafe.Pointer
type free func(ptr unsafe.Pointer)
type memcpy func(dst, src unsafe.Pointer, size uint64)
type strlen func(s *byte) uint64
type strncpy func(dst, src *byte, size uint64)
