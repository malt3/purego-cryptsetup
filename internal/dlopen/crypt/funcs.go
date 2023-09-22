package crypt

import (
	"unsafe"

	"github.com/malt3/purego-cryptsetup/internal/ctypes"
)

func Init(cd **CryptDevice, device *byte) int {
	return int(crypt_init_dl(cd, device))
}

func InitByName(cd **CryptDevice, name *byte) int {
	return int(crypt_init_by_name_dl(cd, name))
}

func Free(cd *CryptDevice) {
	crypt_free_dl(cd)
}

func Dump(cd *CryptDevice) int {
	return int(crypt_dump_dl(cd))
}

func GetType(cd *CryptDevice) *byte {
	return crypt_get_type_dl(cd)
}

func Format(
	cd *CryptDevice,
	typ *byte,
	cipher *byte,
	cipher_mode *byte,
	uuid *byte,
	volume_key *byte,
	volume_key_size uint64,
	params unsafe.Pointer,
) int {
	return int(crypt_format_dl(cd, typ, cipher, cipher_mode, uuid, volume_key, ctypes.SizeT(volume_key_size), params))
}

func Wipe(
	cd *CryptDevice,
	dev_path *byte,
	crypt_wipe_pattern uint32,
	offset uint64,
	length uint64,
	wipe_block_size uint64,
	flags uint32,
	progress unsafe.Pointer,
	usrptr unsafe.Pointer,
) int {
	return int(crypt_wipe_dl(cd, dev_path, crypt_wipe_pattern, offset, length, ctypes.SizeT(wipe_block_size), flags, progress, usrptr))
}

func Resize(cd *CryptDevice, name *byte, new_size uint64) int {
	return int(crypt_resize_dl(cd, name, new_size))
}

func Load(cd *CryptDevice, requested_type *byte, params unsafe.Pointer) int {
	return int(crypt_load_dl(cd, requested_type, params))
}

func KeyslotAddByVolumeKey(
	cd *CryptDevice,
	keyslot uint32,
	volume_key *byte,
	volume_key_size uint64,
	passphrase *byte,
	passphrase_size uint64,
) int {
	return int(crypt_keyslot_add_by_volume_key_dl(cd, ctypes.Int(keyslot), volume_key, ctypes.SizeT(volume_key_size), passphrase, ctypes.SizeT(passphrase_size)))
}

func KeyslotAddByPassphrase(
	cd *CryptDevice,
	keyslot uint32,
	passphrase *byte,
	passphrase_size uint64,
	new_passphrase *byte,
	new_passphrase_size uint64,
) int {
	return int(crypt_keyslot_add_by_passphrase_dl(cd, ctypes.Int(keyslot), passphrase, ctypes.SizeT(passphrase_size), new_passphrase, ctypes.SizeT(new_passphrase_size)))
}

func KeyslotChangeByPassphrase(
	cd *CryptDevice,
	keyslot_old uint32,
	keyslot_new uint32,
	passphrase *byte,
	passphrase_size uint64,
	new_passphrase *byte,
	new_passphrase_size uint64,
) int {
	return crypt_keyslot_change_by_passphrase_dl(cd, keyslot_old, keyslot_new, passphrase, passphrase_size, new_passphrase, new_passphrase_size)
}

func ActivateByPassphrase(
	cd *CryptDevice,
	name *byte,
	keyslot uint32,
	passphrase *byte,
	passphrase_size uint64,
	flags uint32,
) int {
	return crypt_activate_by_passphrase_dl(cd, name, keyslot, passphrase, passphrase_size, flags)
}

func ActivateByToken(
	cd *CryptDevice,
	name *byte,
	token uint32,
	usrptr unsafe.Pointer,
	flags uint32,
) int {
	return crypt_activate_by_token_dl(cd, name, token, usrptr, flags)
}

func ActivateByVolumeKey(
	cd *CryptDevice,
	name *byte,
	volume_key *byte,
	volume_key_size uint64,
	flags uint32,
) int {
	return crypt_activate_by_volume_key_dl(cd, name, volume_key, volume_key_size, flags)
}

func Deactivate(cd *CryptDevice, name *byte) int {
	return crypt_deactivate_dl(cd, name)
}

func SetDebugLevel(level int32) {
	crypt_set_debug_level_dl(level)
}

func GetVolumeKeySize(cd *CryptDevice) int {
	return crypt_get_volume_key_size_dl(cd)
}

func VolumeKeyGet(
	cd *CryptDevice,
	keyslot int32,
	volume_key *byte,
	volume_key_size *uint64,
	passphrase *byte,
	passphrase_size uint64,
) int {
	return crypt_volume_key_get_dl(cd, keyslot, volume_key, volume_key_size, passphrase, passphrase_size)
}

func GetDeviceName(cd *CryptDevice) *byte {
	return crypt_get_device_name_dl(cd)
}

func GetUUID(cd *CryptDevice) *byte {
	return crypt_get_uuid_dl(cd)
}

func TokenJSONGet(cd *CryptDevice, token uint32, json **byte) int {
	return crypt_token_json_get_dl(cd, token, json)
}

func TokenJSONSet(cd *CryptDevice, token uint32, json *byte) int {
	return crypt_token_json_set_dl(cd, token, json)
}

func TokenLUKS2KeyringGet(cd *CryptDevice, token uint32, params *TokenParamsLUKS2Keyring) int {
	return crypt_token_luks2_keyring_get_dl(cd, token, params)
}

func TokenLUKS2KeyringSet(cd *CryptDevice, token uint32, params *TokenParamsLUKS2Keyring) int {
	return crypt_token_luks2_keyring_set_dl(cd, token, params)
}

func TokenAssignKeyslot(cd *CryptDevice, token, keyslot uint32) int {
	return crypt_token_assign_keyslot_dl(cd, token, keyslot)
}

func TokenUnassignKeyslot(cd *CryptDevice, token, keyslot uint32) int {
	return crypt_token_unassign_keyslot_dl(cd, token, keyslot)
}

func TokenIsAssigned(cd *CryptDevice, token, keyslot uint32) int {
	return crypt_token_is_assigned_dl(cd, token, keyslot)
}

func TokenStatus(cd *CryptDevice, token uint32, typ **byte) int {
	return crypt_token_status_dl(cd, token, typ)
}

func SetLogCallback(cd *CryptDevice, log unsafe.Pointer, usrptr unsafe.Pointer) {
	crypt_set_log_callback_dl(cd, log, usrptr)
}
