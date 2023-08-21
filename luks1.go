package cryptsetup

import (
	"unsafe"

	"github.com/malt3/purego-cryptsetup/internal/dlopen/crypt"
	"github.com/malt3/purego-cryptsetup/internal/strings"
)

// LUKS1 is the struct used to manipulate LUKS1 devices.
type LUKS1 struct {
	Hash          string
	DataAlignment int
	DataDevice    string
}

// Name returns the LUKS1 device type name as a string.
func (luks1 LUKS1) Name() string {
	return CRYPT_LUKS1
}

// Unmanaged is used to specialize LUKS1.
func (luks1 LUKS1) Unmanaged() (unsafe.Pointer, func()) {
	deallocations := make([]func(), 0, 2)
	deallocate := func() {
		for index := 0; index < len(deallocations); index++ {
			deallocations[index]()
		}
	}

	var cParams crypt.ParamsLUKS1

	cParams.DataAlignment = uint64(luks1.DataAlignment)

	cParams.Hash = strings.CString(luks1.Hash)
	deallocations = append(deallocations, func() {
		strings.CFree(cParams.Hash)
	})

	cParams.DataDevice = nil
	if luks1.DataDevice != "" {
		cParams.DataDevice = strings.CString(luks1.DataDevice)
		deallocations = append(deallocations, func() {
			strings.CFree(cParams.DataDevice)
		})
	}

	return unsafe.Pointer(&cParams), deallocate
}
