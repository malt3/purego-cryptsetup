//go:build linux

package libc

import (
	"sync"

	"github.com/ebitengine/purego"
)

var dlopenMux = sync.Mutex{}

var libcDL uintptr

const libcSO = "libc.so.6"

func OpenLibc() error {
	dlopenMux.Lock()
	defer dlopenMux.Unlock()

	if libcDL != 0 {
		return nil
	}
	var err error
	libcDL, err = purego.Dlopen(libcSO, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		libcDL = 0
		return err
	}

	malloc_raw, err := purego.Dlsym(libcDL, "malloc")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&malloc_dl, malloc_raw)

	free_raw, err := purego.Dlsym(libcDL, "free")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&free_dl, free_raw)

	memcpy, err := purego.Dlsym(libcDL, "memcpy")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&memcpy_dl, memcpy)

	strlen, err := purego.Dlsym(libcDL, "strlen")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&strlen_dl, strlen)

	strncpy, err := purego.Dlsym(libcDL, "strncpy")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&strncpy_dl, strncpy)

	return nil
}
