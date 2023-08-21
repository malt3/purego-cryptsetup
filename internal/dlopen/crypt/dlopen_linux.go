//go:build linux

package crypt

import (
	"sync"

	"github.com/ebitengine/purego"
)

var dlopenMux = sync.Mutex{}

var cryptsetupDL uintptr

const cryptsetupSO = "libcryptsetup.so.12"

func OpenCryptsetup() error {
	dlopenMux.Lock()
	defer dlopenMux.Unlock()

	if cryptsetupDL != 0 {
		return nil
	}
	var err error
	cryptsetupDL, err = purego.Dlopen(cryptsetupSO, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		cryptsetupDL = 0
		return err
	}

	crypt_init_raw, err := purego.Dlsym(cryptsetupDL, "crypt_init")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_init_dl, crypt_init_raw)

	crypt_init_by_name_raw, err := purego.Dlsym(cryptsetupDL, "crypt_init_by_name")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_init_by_name_dl, crypt_init_by_name_raw)

	crypt_free_raw, err := purego.Dlsym(cryptsetupDL, "crypt_free")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_free_dl, crypt_free_raw)

	crypt_dump_raw, err := purego.Dlsym(cryptsetupDL, "crypt_dump")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_dump_dl, crypt_dump_raw)

	crypt_get_type_raw, err := purego.Dlsym(cryptsetupDL, "crypt_get_type")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_get_type_dl, crypt_get_type_raw)

	crypt_format_raw, err := purego.Dlsym(cryptsetupDL, "crypt_format")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_format_dl, crypt_format_raw)

	crypt_wipe_raw, err := purego.Dlsym(cryptsetupDL, "crypt_wipe")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_wipe_dl, crypt_wipe_raw)

	crypt_resize_raw, err := purego.Dlsym(cryptsetupDL, "crypt_resize")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_resize_dl, crypt_resize_raw)

	crypt_load_raw, err := purego.Dlsym(cryptsetupDL, "crypt_load")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_load_dl, crypt_load_raw)

	crypt_keyslot_add_by_volume_key_raw, err := purego.Dlsym(cryptsetupDL, "crypt_keyslot_add_by_volume_key")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_keyslot_add_by_volume_key_dl, crypt_keyslot_add_by_volume_key_raw)

	crypt_keyslot_add_by_passphrase_raw, err := purego.Dlsym(cryptsetupDL, "crypt_keyslot_add_by_passphrase")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_keyslot_add_by_passphrase_dl, crypt_keyslot_add_by_passphrase_raw)

	crypt_keyslot_change_by_passphrase_raw, err := purego.Dlsym(cryptsetupDL, "crypt_keyslot_change_by_passphrase")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_keyslot_change_by_passphrase_dl, crypt_keyslot_change_by_passphrase_raw)

	crypt_activate_by_passphrase_raw, err := purego.Dlsym(cryptsetupDL, "crypt_activate_by_passphrase")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_activate_by_passphrase_dl, crypt_activate_by_passphrase_raw)

	crypt_activate_by_token_raw, err := purego.Dlsym(cryptsetupDL, "crypt_activate_by_token")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_activate_by_token_dl, crypt_activate_by_token_raw)

	crypt_activate_by_volume_key_raw, err := purego.Dlsym(cryptsetupDL, "crypt_activate_by_volume_key")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_activate_by_volume_key_dl, crypt_activate_by_volume_key_raw)

	crypt_deactivate_raw, err := purego.Dlsym(cryptsetupDL, "crypt_deactivate")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_deactivate_dl, crypt_deactivate_raw)

	crypt_set_debug_level_raw, err := purego.Dlsym(cryptsetupDL, "crypt_set_debug_level")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_set_debug_level_dl, crypt_set_debug_level_raw)

	crypt_get_volume_key_size_raw, err := purego.Dlsym(cryptsetupDL, "crypt_get_volume_key_size")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_get_volume_key_size_dl, crypt_get_volume_key_size_raw)

	crypt_volume_key_get_raw, err := purego.Dlsym(cryptsetupDL, "crypt_volume_key_get")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_volume_key_get_dl, crypt_volume_key_get_raw)

	crypt_get_device_name_raw, err := purego.Dlsym(cryptsetupDL, "crypt_get_device_name")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_get_device_name_dl, crypt_get_device_name_raw)

	crypt_get_uuid_raw, err := purego.Dlsym(cryptsetupDL, "crypt_get_uuid")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_get_uuid_dl, crypt_get_uuid_raw)

	crypt_token_json_get_raw, err := purego.Dlsym(cryptsetupDL, "crypt_token_json_get")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_token_json_get_dl, crypt_token_json_get_raw)

	crypt_token_json_set_raw, err := purego.Dlsym(cryptsetupDL, "crypt_token_json_set")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_token_json_set_dl, crypt_token_json_set_raw)

	crypt_token_luks2_keyring_get_raw, err := purego.Dlsym(cryptsetupDL, "crypt_token_luks2_keyring_get")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_token_luks2_keyring_get_dl, crypt_token_luks2_keyring_get_raw)

	crypt_token_luks2_keyring_set_raw, err := purego.Dlsym(cryptsetupDL, "crypt_token_luks2_keyring_set")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_token_luks2_keyring_set_dl, crypt_token_luks2_keyring_set_raw)

	crypt_token_assign_keyslot_raw, err := purego.Dlsym(cryptsetupDL, "crypt_token_assign_keyslot")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_token_assign_keyslot_dl, crypt_token_assign_keyslot_raw)

	crypt_token_unassign_keyslot_raw, err := purego.Dlsym(cryptsetupDL, "crypt_token_unassign_keyslot")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_token_unassign_keyslot_dl, crypt_token_unassign_keyslot_raw)

	crypt_token_is_assigned_raw, err := purego.Dlsym(cryptsetupDL, "crypt_token_is_assigned")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_token_is_assigned_dl, crypt_token_is_assigned_raw)

	crypt_token_status_raw, err := purego.Dlsym(cryptsetupDL, "crypt_token_status")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_token_status_dl, crypt_token_status_raw)

	crypt_set_log_callback_raw, err := purego.Dlsym(cryptsetupDL, "crypt_set_log_callback")
	if err != nil {
		return err
	}
	purego.RegisterFunc(&crypt_set_log_callback_dl, crypt_set_log_callback_raw)

	return nil
}
