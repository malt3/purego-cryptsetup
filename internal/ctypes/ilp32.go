//go:build 386 || arm

package ctypes

type (
	Int       int32
	Uint      uint32
	Long      int32
	ULong     uint32
	ULongLong uint64
	SizeT     uint32
)
