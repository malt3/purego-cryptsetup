package cryptsetup

import (
	"unsafe"

	"github.com/malt3/purego-cryptsetup/internal/dlopen/crypt"
	"github.com/malt3/purego-cryptsetup/internal/strings"
)

type Plain struct {
	Hash       string
	Offset     uint64
	Skip       uint64
	Size       uint64
	SectorSize uint32
}

// Name returns the PLAIN device type name as a string.
func (plain Plain) Name() string {
	return "PLAIN"
}

func (plain Plain) Unmanaged() (unsafe.Pointer, func()) {
	deallocations := make([]func(), 0, 1)
	deallocate := func() {
		for index := 0; index < len(deallocations); index++ {
			deallocations[index]()
		}
	}

	var cParams crypt.ParamsPlain

	cParams.Offset = plain.Offset
	cParams.Skip = plain.Skip
	cParams.Size = plain.Size
	cParams.SectorSize = plain.SectorSize

	cParams.Hash = strings.CString(plain.Hash)
	deallocations = append(deallocations, func() {
		strings.CFree(cParams.Hash)
	})

	return unsafe.Pointer(&cParams), deallocate
}
