# Pure Go bindings for libcryptsetup

This project is a drop-in replacement for the excellent [go-cryptsetup](https://github.com/martinjungblut/go-cryptsetup) library, using `dlopen` / `dlsym` to load the libcryptsetup library at runtime.
This allows the code to be compiled on systems without libcryptsetup installed, and to be used with different versions of libcryptsetup.

This method of runtime discovery is also used by [systemd](https://github.com/poettering/systemd/blob/a52dc0b6f3808c2211216ff46ab98ab0bec19200/src/shared/cryptsetup-util.c).

Please refer to the original project for documentation and examples.

## Warning

This project is work in progress and not yet ready for production use.
