package cryptsetup

import (
	"unsafe"

	"github.com/malt3/purego-cryptsetup/internal/strings"
)

var logCallback func(level int, message string)

func log_callback(level uint32, message *byte, usrptr unsafe.Pointer) {
	if logCallback != nil {
		logCallback(int(level), strings.GoString(message))
	}
}

func SetLogCallback(newLogCallback func(level int, message string)) {
	mustInitialize()

	// TODO: purego.NewCallback is not supported on Linux
	// https://github.com/ebitengine/purego/issues/124
	newLogCallback(0, "Warning: SetLogCallback is not yet supported")

	// logCallback = newLogCallback
	// callBack := purego.NewCallback(log_callback)

	// crypt.SetLogCallback(nil, unsafe.Pointer(callBack), nil)
}

var progressCallback func(size, offset uint64) int

func progress_callback(size uint64, offset uint64, usrptr unsafe.Pointer) int {
	if progressCallback != nil {
		ret := progressCallback(uint64(size), uint64(offset))
		return ret
	}
	return 0
}
