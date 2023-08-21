//go:build cryptsetup2.4

// TODO: choose if / how those should be loaded
package dlopen

import "unsafe"

var crypt_dump_json_dl func(
	*crypt_device, // cd
	**char, // json
	uint32, // flags
) int32

var crypt_activate_by_token_pin_dl func(
	*crypt_device, // cd
	*char, // name
	*char, // type
	int32, // token
	*char, // pin
	*uint64, // pin_size
	unsafe.Pointer, // usrptr
	uint32, // flags
) int32

var crypt_token_external_disable_dl func()

var crypt_token_external_path_dl func() *char

var crypt_token_max_dl func(
	*char, //type
) int32
