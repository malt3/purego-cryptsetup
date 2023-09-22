//go:build (amd64 || arm64) && !windows

package ctypes

type (
	Int       int32
	Uint      uint32
	Long      int64
	ULong     uint64
	ULongLong uint64
	SizeT     uint64
)
