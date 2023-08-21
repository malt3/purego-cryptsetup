package cryptsetup

import (
	"unsafe"

	"github.com/malt3/purego-cryptsetup/internal/dlopen/crypt"
	"github.com/malt3/purego-cryptsetup/internal/dlopen/libc"
	"github.com/malt3/purego-cryptsetup/internal/strings"
)

// LUKS2 is the struct used to manipulate LUKS2 devices.
type LUKS2 struct {
	PBKDFType       *PbkdfType
	Integrity       string
	IntegrityParams *IntegrityParams
	DataAlignment   int
	DataDevice      string
	SectorSize      uint32
	Label           string
	Subsystem       string
}

type PbkdfType struct {
	Type            string
	Hash            string
	TimeMs          uint32
	Iterations      uint32
	MaxMemoryKb     uint32
	ParallelThreads uint32
	Flags           uint32
}

type IntegrityParams struct {
	JournalSize       uint64
	JournalWatermark  uint
	JournalCommitTime uint

	InterleaveSectors uint32
	TagSize           uint32
	SectorSize        uint32
	BufferSectors     uint32

	Integrity        string
	IntegrityKeySize uint32

	JournalIntegrity        string
	JournalIntegrityKey     string
	JournalIntegrityKeySize uint32

	JournalCrypt        string
	JournalCryptKey     string
	JournalCryptKeySize uint32
}

// Name returns the LUKS2 device type name as a string.
func (luks2 LUKS2) Name() string {
	return CRYPT_LUKS2
}

// Unmanaged is used to specialize LUKS2.
func (luks2 LUKS2) Unmanaged() (unsafe.Pointer, func()) {
	deallocations := make([]func(), 0)
	deallocate := func() {
		for index := 0; index < len(deallocations); index++ {
			deallocations[index]()
		}
	}

	var cParams crypt.ParamsLUKS2

	cParams.Integrity = nil
	if luks2.Integrity != "" {
		cParams.Integrity = strings.CString(luks2.Integrity)
		deallocations = append(deallocations, func() {
			strings.CFree(cParams.Integrity)
		})
	}

	cParams.DataAlignment = uint64(luks2.DataAlignment)

	cParams.DataDevice = nil
	if luks2.DataDevice != "" {
		cParams.DataDevice = strings.CString(luks2.DataDevice)
		deallocations = append(deallocations, func() {
			strings.CFree(cParams.DataDevice)
		})
	}

	cParams.SectorSize = uint32(luks2.SectorSize)

	cParams.Label = nil
	if luks2.Label != "" {
		cParams.Label = strings.CString(luks2.Label)
		deallocations = append(deallocations, func() {
			strings.CFree(cParams.Label)
		})
	}

	cParams.Subsystem = nil
	if luks2.Subsystem != "" {
		cParams.Subsystem = strings.CString(luks2.Subsystem)
		deallocations = append(deallocations, func() {
			strings.CFree(cParams.Subsystem)
		})
	}

	cParams.PBKDF = nil
	if luks2.PBKDFType != nil {
		cPBKDFType := (*crypt.PBKDFType)(libc.Malloc((uint64)(crypt.SizeofPBKDFType)))

		cPBKDFType.Type = nil
		if luks2.PBKDFType.Type != "" {
			cPBKDFType.Type = strings.CString(luks2.PBKDFType.Type)
			deallocations = append(deallocations, func() {
				strings.CFree(cPBKDFType.Type)
			})
		}

		cPBKDFType.Hash = nil
		if luks2.PBKDFType.Hash != "" {
			cPBKDFType.Hash = strings.CString(luks2.PBKDFType.Hash)
			deallocations = append(deallocations, func() {
				strings.CFree(cPBKDFType.Hash)
			})
		}

		cPBKDFType.TimeMs = luks2.PBKDFType.TimeMs
		cPBKDFType.Iterations = luks2.PBKDFType.Iterations
		cPBKDFType.MaxMemoryKb = luks2.PBKDFType.MaxMemoryKb
		cPBKDFType.ParallelThreads = luks2.PBKDFType.ParallelThreads
		cPBKDFType.Flags = luks2.PBKDFType.Flags

		deallocations = append(deallocations, func() {
			strings.Free(cPBKDFType)
		})

		cParams.PBKDF = cPBKDFType
	}

	cParams.IntegrityParams = nil
	if luks2.IntegrityParams != nil {
		cIntegrityParams := (*crypt.ParamsIntegrity)(libc.Malloc(uint64(crypt.SizeofParamsIntegrity)))

		cIntegrityParams.JournalSize = uint64(luks2.IntegrityParams.JournalSize)
		cIntegrityParams.JournalWatermark = uint32(luks2.IntegrityParams.JournalWatermark)
		cIntegrityParams.JournalCommitTime = uint32(luks2.IntegrityParams.JournalCommitTime)

		cIntegrityParams.InterleaveSectors = uint32(luks2.IntegrityParams.InterleaveSectors)
		cIntegrityParams.TagSize = uint32(luks2.IntegrityParams.TagSize)
		cIntegrityParams.SectorSize = uint32(luks2.IntegrityParams.SectorSize)
		cIntegrityParams.BufferSectors = uint32(luks2.IntegrityParams.BufferSectors)

		cIntegrityParams.Integrity = nil
		if luks2.IntegrityParams.Integrity != "" {
			cIntegrityParams.Integrity = strings.CString(luks2.IntegrityParams.Integrity)
			deallocations = append(deallocations, func() {
				strings.CFree(cIntegrityParams.Integrity)
			})
		}
		cIntegrityParams.IntegrityKeySize = luks2.IntegrityParams.IntegrityKeySize

		cIntegrityParams.JournalIntegrity = nil
		if luks2.IntegrityParams.JournalIntegrity != "" {
			cIntegrityParams.JournalIntegrity = strings.CString(luks2.IntegrityParams.JournalIntegrity)
			deallocations = append(deallocations, func() {
				strings.CFree(cIntegrityParams.JournalIntegrity)
			})
		}
		cIntegrityParams.JournalIntegrityKey = nil
		if luks2.IntegrityParams.JournalIntegrityKey != "" {
			cIntegrityParams.JournalIntegrityKey = strings.CString(luks2.IntegrityParams.JournalIntegrityKey)
			deallocations = append(deallocations, func() {
				strings.CFree(cIntegrityParams.JournalIntegrityKey)
			})
		}
		cIntegrityParams.JournalIntegrityKeySize = uint32(luks2.IntegrityParams.JournalIntegrityKeySize)

		cIntegrityParams.JournalCrypt = nil
		if luks2.IntegrityParams.JournalCrypt != "" {
			cIntegrityParams.JournalCrypt = strings.CString(luks2.IntegrityParams.JournalCrypt)
			deallocations = append(deallocations, func() {
				strings.CFree(cIntegrityParams.JournalCrypt)
			})
		}
		cIntegrityParams.JournalCryptKey = nil
		if luks2.IntegrityParams.JournalCryptKey != "" {
			cIntegrityParams.JournalCryptKey = strings.CString(luks2.IntegrityParams.JournalCryptKey)
			deallocations = append(deallocations, func() {
				strings.CFree(cIntegrityParams.JournalCryptKey)
			})
		}
		cIntegrityParams.JournalCryptKeySize = uint32(luks2.IntegrityParams.JournalCryptKeySize)

		deallocations = append(deallocations, func() {
			strings.Free(cIntegrityParams)
		})

		cParams.IntegrityParams = cIntegrityParams
	}

	return unsafe.Pointer(&cParams), deallocate
}

// TokenParamsLUKS2KeyRing defines LUKS2 keyring token parameters.
type TokenParamsLUKS2Keyring struct {
	KeyDescription string
}
