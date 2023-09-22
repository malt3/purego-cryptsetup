package crypt

import (
	"unsafe"

	"github.com/malt3/purego-cryptsetup/internal/ctypes"
)

var (
	crypt_init_dl                         crypt_init
	crypt_init_by_name_dl                 crypt_init_by_name
	crypt_free_dl                         crypt_free
	crypt_dump_dl                         crypt_dump
	crypt_get_type_dl                     crypt_get_type
	crypt_format_dl                       crypt_format
	crypt_wipe_dl                         crypt_wipe
	crypt_resize_dl                       crypt_resize
	crypt_load_dl                         crypt_load
	crypt_keyslot_add_by_volume_key_dl    crypt_keyslot_add_by_volume_key
	crypt_keyslot_add_by_passphrase_dl    crypt_keyslot_add_by_passphrase
	crypt_keyslot_change_by_passphrase_dl crypt_keyslot_change_by_passphrase
	crypt_activate_by_passphrase_dl       crypt_activate_by_passphrase
	crypt_activate_by_token_dl            crypt_activate_by_token
	crypt_activate_by_volume_key_dl       crypt_activate_by_volume_key
	crypt_deactivate_dl                   crypt_deactivate
	crypt_set_debug_level_dl              crypt_set_debug_level
	crypt_get_volume_key_size_dl          crypt_get_volume_key_size
	crypt_volume_key_get_dl               crypt_volume_key_get
	crypt_get_device_name_dl              crypt_get_device_name
	crypt_get_uuid_dl                     crypt_get_uuid
	crypt_token_json_get_dl               crypt_token_json_get
	crypt_token_json_set_dl               crypt_token_json_set
	crypt_token_luks2_keyring_get_dl      crypt_token_luks2_keyring_get
	crypt_token_luks2_keyring_set_dl      crypt_token_luks2_keyring_set
	crypt_token_assign_keyslot_dl         crypt_token_assign_keyslot
	crypt_token_unassign_keyslot_dl       crypt_token_unassign_keyslot
	crypt_token_is_assigned_dl            crypt_token_is_assigned
	crypt_token_status_dl                 crypt_token_status
	crypt_set_log_callback_dl             crypt_set_log_callback
)

type crypt_init func(
	**CryptDevice, // cd
	*byte, // device
) ctypes.Int

type crypt_init_by_name func(
	**CryptDevice, // cd
	*byte, // name
) ctypes.Int

type crypt_free func(
	*CryptDevice, // cd
)
type crypt_dump func(
	*CryptDevice, // cd
) ctypes.Int

type crypt_get_type func(
	*CryptDevice, // cd
) *byte

type crypt_format func(
	*CryptDevice, // cd
	*byte, // type
	*byte, // cipher
	*byte, // cipher_mode
	*byte, // uuid
	*byte, // volume_key
	ctypes.SizeT, // volume_key_size
	unsafe.Pointer, // params
) ctypes.Int

type crypt_wipe func(
	*CryptDevice, // cd
	*byte, // dev_path
	uint32, // crypt_wipe_pattern
	uint64, // offset
	uint64, // length
	ctypes.SizeT, // wipe_block_size
	uint32, // flags
	unsafe.Pointer, // progress
	unsafe.Pointer, // usrptr
) ctypes.Int

type crypt_resize func(
	*CryptDevice, // cd
	*byte, // name
	uint64, // new_size
) ctypes.Int

type crypt_load func(
	*CryptDevice, // cd
	*byte, // requested_type
	unsafe.Pointer, // params
) ctypes.Int

type crypt_keyslot_add_by_volume_key func(
	*CryptDevice, // cd
	ctypes.Int, // keyslot
	*byte, // volume_key
	ctypes.SizeT, // volume_key_size
	*byte, // passphrase
	ctypes.SizeT, // passphrase_size
) ctypes.Int

type crypt_keyslot_add_by_passphrase func(
	*CryptDevice, // cd
	ctypes.Int, // keyslot
	*byte, // passphrase
	ctypes.SizeT, // passphrase_size
	*byte, // new_passphrase
	ctypes.SizeT, // new_passphrase_size
) ctypes.Int

type crypt_keyslot_change_by_passphrase func(
	*CryptDevice, // cd
	ctypes.Int, // keyslot_old
	ctypes.Int, // keyslot_new
	*byte, // passphrase
	ctypes.SizeT, // passphrase_size
	*byte, // new_passphrase
	ctypes.SizeT, // new_passphrase_size
) ctypes.Int

type crypt_activate_by_passphrase func(
	*CryptDevice, // cd
	*byte, // name
	ctypes.Int, // keyslot
	*byte, // passphrase
	ctypes.SizeT, // passphrase_size
	uint32, // flags
) ctypes.Int

type crypt_activate_by_token func(
	*CryptDevice, // cd
	*byte, // name
	ctypes.Int, // token
	unsafe.Pointer, // usrptr
	uint32, // flags
) ctypes.Int

type crypt_activate_by_volume_key func(
	*CryptDevice, // cd
	*byte, // name
	*byte, // volume_key
	ctypes.SizeT, // volume_key_size
	uint32, // flags
) ctypes.Int

type crypt_deactivate func(
	*CryptDevice, // cd
	*byte, // name
) ctypes.Int

type crypt_set_debug_level func(
	ctypes.Int, // level
)
type crypt_get_volume_key_size func(
	*CryptDevice, // cd
) ctypes.Int

type crypt_volume_key_get func(
	*CryptDevice, // cd
	ctypes.Int, // keyslot
	*byte, // volume_key
	*ctypes.SizeT, // volume_key_size
	*byte, // passphrase
	ctypes.SizeT, // passphrase_size
) ctypes.Int

type crypt_get_device_name func(
	*CryptDevice, // cd
) *byte

type crypt_get_uuid func(
	*CryptDevice, // cd
) *byte

type crypt_token_json_get func(
	*CryptDevice, // cd
	ctypes.Int, // token
	**byte, // json
) ctypes.Int

type crypt_token_json_set func(
	*CryptDevice, // cd
	ctypes.Int, // token
	*byte, // json
) ctypes.Int

type crypt_token_luks2_keyring_get func(
	*CryptDevice, // cd
	ctypes.Int, // token
	*TokenParamsLUKS2Keyring, // params
) ctypes.Int

type crypt_token_luks2_keyring_set func(
	*CryptDevice, // cd
	ctypes.Int, // token
	*TokenParamsLUKS2Keyring, // params
) ctypes.Int

type crypt_token_assign_keyslot func(
	*CryptDevice, // cd
	ctypes.Int, // token
	ctypes.Int, // keyslot
) ctypes.Int

type crypt_token_unassign_keyslot func(
	*CryptDevice, // cd
	ctypes.Int, // token
	ctypes.Int, // keyslot
) ctypes.Int

type crypt_token_is_assigned func(
	*CryptDevice, // cd
	ctypes.Int, // token
	ctypes.Int, // keyslot
) ctypes.Int

type crypt_token_status func(
	*CryptDevice, // cd
	ctypes.Int, // token
	**byte, // type
) ctypes.Int

type crypt_set_log_callback func(
	*CryptDevice, // cd
	unsafe.Pointer, // log
	unsafe.Pointer, // usrptr
)

type CryptDevice unsafe.Pointer

// TODO: choose
// type crypt_device C.struct_crypt_device
// type Crypt_device cgo.Incomplete

type ParamsPlain struct {
	Hash       *byte
	Offset     uint64
	Skip       uint64
	Size       uint64
	SectorSize uint32
	_          [4]byte
}

type TokenParamsLUKS2Keyring struct {
	KeyDescription *byte
}

const SizeofTokenParamsLUKS2Keyring = unsafe.Sizeof(TokenParamsLUKS2Keyring{})

type ParamsLUKS1 struct {
	Hash          *byte
	DataAlignment ctypes.SizeT
	DataDevice    *byte
}

type ParamsLUKS2 struct {
	PBKDF           *PBKDFType
	Integrity       *byte
	IntegrityParams *ParamsIntegrity
	DataAlignment   ctypes.SizeT
	DataDevice      *byte
	SectorSize      uint32
	Label           *byte
	Subsystem       *byte
}

type PBKDFType struct {
	Type            *byte
	Hash            *byte
	TimeMs          uint32
	Iterations      uint32
	MaxMemoryKb     uint32
	ParallelThreads uint32
	Flags           uint32
	_               [4]byte
}

const SizeofPBKDFType = unsafe.Sizeof(PBKDFType{})

type ParamsIntegrity struct {
	JournalSize             uint64
	JournalWatermark        ctypes.Uint
	JournalCommitTime       ctypes.Uint
	InterleaveSectors       uint32
	TagSize                 uint32
	SectorSize              uint32
	BufferSectors           uint32
	Integrity               *byte
	IntegrityKeySize        uint32
	JournalIntegrity        *byte
	JournalIntegrityKey     *byte
	JournalIntegrityKeySize uint32
	JournalCrypt            *byte
	JournalCryptKey         *byte
	JournalCryptKeySize     uint32
	_                       [4]byte
}

const SizeofParamsIntegrity = unsafe.Sizeof(ParamsIntegrity{})
