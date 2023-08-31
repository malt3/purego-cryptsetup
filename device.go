package cryptsetup

import (
	"unsafe"

	"github.com/malt3/purego-cryptsetup/internal/dlopen/crypt"
	"github.com/malt3/purego-cryptsetup/internal/dlopen/libc"
	"github.com/malt3/purego-cryptsetup/internal/strings"
)

// Device is a handle to the crypto device.
// It encapsulates libcryptsetup's 'crypt_device' struct.
type Device struct {
	cryptDevice *crypt.CryptDevice
	freed       bool
}

// Init initializes a crypt device backed by 'devicePath'.
// Returns a pointer to the newly allocated Device or any error encountered.
// C equivalent: crypt_init
func Init(devicePath string) (*Device, error) {
	if err := ensureIntialized(); err != nil {
		return nil, err
	}

	cryptDevicePath := strings.CString(devicePath)
	defer strings.CFree(cryptDevicePath)

	var cryptDevice *crypt.CryptDevice
	if err := int(crypt.Init(&cryptDevice, cryptDevicePath)); err < 0 {
		return nil, &Error{functionName: "crypt_init", code: err}
	}

	return &Device{cryptDevice: cryptDevice}, nil
}

// InitByName initializes a crypt device from provided active device 'name'.
// Returns a pointer to the newly allocated Device or any error encountered.
// C equivalent: crypt_init_by_name
func InitByName(name string) (*Device, error) {
	if err := ensureIntialized(); err != nil {
		return nil, err
	}

	activeCryptDeviceName := strings.CString(name)
	defer strings.CFree(activeCryptDeviceName)

	var cryptDevice *crypt.CryptDevice
	if err := int(crypt.InitByName(&cryptDevice, activeCryptDeviceName)); err < 0 {
		return nil, &Error{functionName: "crypt_init_by_name", code: err}
	}

	return &Device{cryptDevice: cryptDevice}, nil
}

// Free releases crypt device context and used memory.
// C equivalent: crypt_free
func (device *Device) Free() bool {
	if !device.freed {
		crypt.Free(device.cryptDevice)
		device.freed = true
		return true
	}
	return false
}

// C equivalent: crypt_dump
func (device *Device) Dump() int {
	return int(crypt.Dump(device.cryptDevice))
}

// Type returns the device's type as a string.
// Returns an empty string if the information is not available.
func (device *Device) Type() string {
	return strings.GoString(crypt.GetType(device.cryptDevice))
}

// Format formats a Device, using a specific device type, and type-independent parameters.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_format
func (device *Device) Format(deviceType DeviceType, genericParams GenericParams) error {
	cryptDeviceTypeName := strings.CString(deviceType.Name())
	defer strings.CFree(cryptDeviceTypeName)

	cCipher := strings.CString(genericParams.Cipher)
	defer strings.CFree(cCipher)

	cCipherMode := strings.CString(genericParams.CipherMode)
	defer strings.CFree(cCipherMode)

	var cUUID *byte = nil
	if len(genericParams.UUID) > 0 {
		cUUID = strings.CString(genericParams.UUID)
		defer strings.CFree(cUUID)
	}

	var cVolumeKey *byte = nil
	if len(genericParams.VolumeKey) > 0 {
		cVolumeKey = strings.CString(genericParams.VolumeKey)
		defer strings.CFree(cVolumeKey)
	}

	cVolumeKeySize := uint64(genericParams.VolumeKeySize)

	cTypeParams, freeCTypeParams := deviceType.Unmanaged()
	defer freeCTypeParams()

	err := crypt.Format(device.cryptDevice, cryptDeviceTypeName, cCipher, cCipherMode, cUUID, cVolumeKey, cVolumeKeySize, cTypeParams)
	if err < 0 {
		return &Error{functionName: "crypt_format", code: int(err)}
	}

	return nil
}

// TODO: export progress_callback

var progressCallback func(size, offset uint64) int

func progress_callback(size, offset uint64, usrptr unsafe.Pointer) int {
	if progressCallback != nil {
		return progressCallback(uint64(size), uint64(offset))
	}
	return 0
}

// Wipe wipes/fills (part of) a device with the selected pattern.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_wipe
func (device *Device) Wipe(devicePath string, pattern int, offset, length uint64, wipeBlockSize, flags int, progress func(size, offset uint64) int) error {
	cWipeBlockSize := uint64(wipeBlockSize)

	cDevicePath := strings.CString(devicePath)
	defer strings.CFree(cDevicePath)

	progressCallback = progress

	// TODO: handle progress callback
	err := crypt.Wipe(device.cryptDevice, cDevicePath, 0, offset, length, cWipeBlockSize, uint32(flags), unsafe.Pointer(nil), nil)
	if err < 0 {
		return &Error{functionName: "crypt_wipe", code: int(err)}
	}

	return nil
}

// Resize the crypt device.
// Set newSize to 0 to use all of the underlying device size
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_resize
func (device *Device) Resize(name string, newSize uint64) error {
	cryptDeviceName := strings.CString(name)
	defer strings.CFree(cryptDeviceName)

	err := crypt.Resize(device.cryptDevice, cryptDeviceName, uint64(newSize))
	if err < 0 {
		return &Error{functionName: "crypt_resize", code: int(err)}
	}

	return nil
}

// Load loads crypt device parameters from the device type parameters if it is
// specified, otherwise it loads the device from the on-disk header.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_load
func (device *Device) Load(deviceType DeviceType) error {
	var cryptDeviceTypeName *byte
	var cTypeParams unsafe.Pointer

	if deviceType != nil {
		cryptDeviceTypeName = strings.CString(deviceType.Name())
		defer strings.CFree(cryptDeviceTypeName)

		var freeCTypeParams func()
		cTypeParams, freeCTypeParams = deviceType.Unmanaged()
		defer freeCTypeParams()
	}

	err := crypt.Load(device.cryptDevice, cryptDeviceTypeName, cTypeParams)
	if err < 0 {
		return &Error{functionName: "crypt_load", code: int(err)}
	}

	return nil
}

// KeyslotAddByVolumeKey adds a key slot using a volume key to perform the required security check.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_keyslot_add_by_volume_key
func (device *Device) KeyslotAddByVolumeKey(keyslot int, volumeKey string, passphrase string) error {
	var cVolumeKey *byte = nil
	if len(volumeKey) > 0 {
		cVolumeKey = strings.CString(volumeKey)
		defer strings.CFree(cVolumeKey)
	}

	cPassphrase := strings.CString(passphrase)
	defer strings.CFree(cPassphrase)

	err := crypt.KeyslotAddByVolumeKey(device.cryptDevice, uint32(keyslot), cVolumeKey, uint64(len(volumeKey)), cPassphrase, uint64(len(passphrase)))
	if err < 0 {
		return &Error{functionName: "crypt_keyslot_add_by_volume_key", code: int(err)}
	}

	return nil
}

// KeyslotAddByPassphrase adds a key slot using a previously added passphrase to perform the required security check.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_keyslot_add_by_passphrase
func (device *Device) KeyslotAddByPassphrase(keyslot int, currentPassphrase string, newPassphrase string) error {
	cCurrentPassphrase := strings.CString(currentPassphrase)
	defer strings.CFree(cCurrentPassphrase)

	cNewPassphrase := strings.CString(newPassphrase)
	defer strings.CFree(cNewPassphrase)

	err := crypt.KeyslotAddByPassphrase(
		device.cryptDevice, uint32(keyslot),
		cCurrentPassphrase, uint64(len(currentPassphrase)),
		cNewPassphrase, uint64(len(newPassphrase)),
	)
	if err < 0 {
		return &Error{functionName: "crypt_keyslot_add_by_passphrase", code: int(err)}
	}

	return nil
}

// KeyslotChangeByPassphrase changes a defined a key slot using a previously added passphrase to perform the required security check.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_keyslot_change_by_passphrase
func (device *Device) KeyslotChangeByPassphrase(currentKeyslot int, newKeyslot int, currentPassphrase string, newPassphrase string) error {
	cCurrentPassphrase := strings.CString(currentPassphrase)
	defer strings.CFree(cCurrentPassphrase)

	cNewPassphrase := strings.CString(newPassphrase)
	defer strings.CFree(cNewPassphrase)

	err := crypt.KeyslotChangeByPassphrase(
		device.cryptDevice,
		uint32(currentKeyslot),
		uint32(newKeyslot),
		cCurrentPassphrase, uint64(len(currentPassphrase)),
		cNewPassphrase, uint64(len(newPassphrase)),
	)
	if err < 0 {
		return &Error{functionName: "crypt_keyslot_change_by_passphrase", code: int(err)}
	}

	return nil
}

// ActivateByPassphrase activates a device by using a passphrase from a specific keyslot.
// If deviceName is empty only check passphrase.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_activate_by_passphrase
func (device *Device) ActivateByPassphrase(deviceName string, keyslot int, passphrase string, flags int) error {
	var cryptDeviceName *byte = nil
	if len(deviceName) > 0 {
		cryptDeviceName = strings.CString(deviceName)
		defer strings.CFree(cryptDeviceName)
	}

	cPassphrase := strings.CString(passphrase)
	defer strings.CFree(cPassphrase)

	err := crypt.ActivateByPassphrase(device.cryptDevice, cryptDeviceName, uint32(keyslot), cPassphrase, uint64(len(passphrase)), uint32(flags))
	if err < 0 {
		return &Error{functionName: "crypt_activate_by_passphrase", code: int(err)}
	}

	return nil
}

// ActivateByToken activates a device or checks key using a token.
// C equivalent: crypt_activate_by_token
func (device *Device) ActivateByToken(deviceName string, token int, usrptr string, flags int) error {
	var cryptDeviceName *byte = nil
	if len(deviceName) > 0 {
		cryptDeviceName = strings.CString(deviceName)
		defer strings.CFree(cryptDeviceName)
	}

	var cUsrptr *byte = nil
	if len(usrptr) > 0 {
		cUsrptr = strings.CString(usrptr)
		defer strings.CFree(cUsrptr)
	}

	err := crypt.ActivateByToken(device.cryptDevice, cryptDeviceName, uint32(token), unsafe.Pointer(cUsrptr), uint32(flags))
	if err < 0 {
		return &Error{functionName: "crypt_activate_by_token", code: int(err)}
	}
	return nil
}

// ActivateByVolumeKey activates a device by using a volume key.
// If deviceName is empty only check passphrase.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_activate_by_volume_key
func (device *Device) ActivateByVolumeKey(deviceName string, volumeKey string, volumeKeySize int, flags int) error {
	var cryptDeviceName *byte = nil
	if len(deviceName) > 0 {
		cryptDeviceName = strings.CString(deviceName)
		defer strings.CFree(cryptDeviceName)
	}

	var cVolumeKey *byte = nil
	if len(volumeKey) > 0 {
		cVolumeKey = strings.CString(volumeKey)
		defer strings.CFree(cVolumeKey)
	}

	err := crypt.ActivateByVolumeKey(device.cryptDevice, cryptDeviceName, cVolumeKey, uint64(volumeKeySize), uint32(flags))
	if err < 0 {
		return &Error{functionName: "crypt_activate_by_volume_key", code: int(err)}
	}

	return nil
}

// Deactivate deactivates a device.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_deactivate
func (device *Device) Deactivate(deviceName string) error {
	cryptDeviceName := strings.CString(deviceName)
	defer strings.CFree(cryptDeviceName)

	err := crypt.Deactivate(device.cryptDevice, cryptDeviceName)
	if err < 0 {
		return &Error{functionName: "crypt_deactivate", code: int(err)}
	}

	return nil
}

// SetDebugLevel sets the debug level for the library.
// C equivalent: crypt_set_debug_level
func SetDebugLevel(debugLevel int) {
	mustInitialize()

	crypt.SetDebugLevel(int32(debugLevel))
}

// VolumeKeyGet gets the volume key from a crypt device.
// Returns a slice of bytes having the volume key and the unlocked key slot number, or an error otherwise.
// C equivalent: crypt_volume_key_get
func (device *Device) VolumeKeyGet(keyslot int, passphrase string) ([]byte, int, error) {
	cPassphrase := strings.CString(passphrase)
	defer strings.CFree(cPassphrase)

	cVKSize := crypt.GetVolumeKeySize(device.cryptDevice)
	cVKSizePointer := libc.Malloc(uint64(cVKSize))
	if cVKSizePointer == nil {
		return []byte{}, 0, &Error{functionName: "malloc"}
	}
	defer libc.Free(cVKSizePointer)

	err := crypt.VolumeKeyGet(
		device.cryptDevice, int32(keyslot),
		(*byte)(cVKSizePointer), (*uint64)(unsafe.Pointer(&cVKSize)),
		cPassphrase, uint64(len(passphrase)),
	)
	if err < 0 {
		return []byte{}, 0, &Error{functionName: "crypt_volume_key_get", code: int(err)}
	}
	return strings.GoBytes((*byte)(cVKSizePointer), uint64(cVKSize)), int(err), nil
}

// GetDeviceName gets the path to the underlying device.
// C equivalent: crypt_get_device_name
func (device *Device) GetDeviceName() string {
	res := crypt.GetDeviceName(device.cryptDevice)
	return strings.GoString(res)
}

// GetUUID gets the device's UUID.
// C equivalent: crypt_get_uuid
func (device *Device) GetUUID() string {
	res := crypt.GetUUID(device.cryptDevice)
	return strings.GoString(res)
}

// TokenJSONGet gets content of a token definition in JSON format.
// C equivalent: crypt_token_json_get
func (device *Device) TokenJSONGet(token int) (string, error) {
	cStr := strings.CString("")
	defer strings.CFree(cStr)

	if res := crypt.TokenJSONGet(device.cryptDevice, uint32(token), &cStr); res < 0 {
		return "", &Error{functionName: "crypt_token_json_get", code: int(res)}
	}

	return strings.GoString(cStr), nil
}

// TokenJSONSet stores content of a token definition in JSON format.
// Use CRYPT_ANY_TOKEN to allocate new one.
// Returns allocated token ID on success, or an error otherwise.
// C equivalent: crypt_token_json_set
func (device *Device) TokenJSONSet(token int, json string) (int, error) {
	cStr := strings.CString(json)
	defer strings.CFree(cStr)

	res := crypt.TokenJSONSet(device.cryptDevice, uint32(token), cStr)
	if res < 0 {
		return -1, &Error{functionName: "crypt_token_json_set", code: int(res)}
	}
	return int(res), nil
}

// TokenLUKS2KeyRingGet gets LUKS2 keyring token params.
// C equivalent: crypt_token_luks2_keyring_get
func (device *Device) TokenLUKS2KeyRingGet(token int) (TokenParamsLUKS2Keyring, error) {
	cParams := (*crypt.TokenParamsLUKS2Keyring)(libc.Malloc(uint64(crypt.SizeofTokenParamsLUKS2Keyring)))
	defer strings.Free(cParams)

	res := crypt.TokenLUKS2KeyringGet(device.cryptDevice, uint32(token), cParams)
	if res < 0 {
		return TokenParamsLUKS2Keyring{}, &Error{functionName: "crypt_token_luks2_keyring_get", code: int(res)}
	}

	return TokenParamsLUKS2Keyring{
		KeyDescription: strings.GoString(cParams.KeyDescription),
	}, nil
}

// TokenLUKS2KeyRingSet creates a new luks2 keyring token.
// C equivalent: crypt_token_luks2_keyring_set
func (device *Device) TokenLUKS2KeyRingSet(token int, params TokenParamsLUKS2Keyring) (int, error) {
	cKeyDescription := strings.CString(params.KeyDescription)
	defer strings.CFree(cKeyDescription)
	cParams := (*crypt.TokenParamsLUKS2Keyring)(libc.Malloc(uint64(crypt.SizeofTokenParamsLUKS2Keyring)))
	defer strings.Free(cParams)
	cParams.KeyDescription = cKeyDescription

	res := crypt.TokenLUKS2KeyringSet(device.cryptDevice, uint32(token), cParams)
	if res < 0 {
		return -1, &Error{functionName: "crypt_token_luks2_keyring_set", code: int(res)}
	}
	return int(res), nil
}

// TokenAssignKeyslot assigns a token to particular keyslot. (There can be more keyslots assigned to one token id.)
// Use CRYPT_ANY_TOKEN to assign all tokens to keyslot.
// Use CRYPT_ANY SLOT to assign all active keyslots to token.
// C equivalent: crypt_token_assign_keyslot
func (device *Device) TokenAssignKeyslot(token int, keyslot int) error {
	res := crypt.TokenAssignKeyslot(device.cryptDevice, uint32(token), uint32(keyslot))

	// libcryptsetup returns the token ID on success
	// In case of CRYPT_ANY_TOKEN, the token ID is -1,
	// so we need to make sure the response is actually an error instead of a token ID
	resAnyToken := token == CRYPT_ANY_TOKEN && int(res) == token
	if res < 0 && !resAnyToken {
		return &Error{functionName: "crypt_token_assign_keyslot", code: int(res)}
	}
	return nil
}

// TokenUnassignKeyslot unassigns a token from particular keyslot.
// There can be more keyslots assigned to one token id.
// Use CRYPT_ANY_TOKEN to unassign all tokens from keyslot.
// Use CRYPT_ANY SLOT to unassign all active keyslots from token.
// C equivalent: crypt_token_unassign_keyslot
func (device *Device) TokenUnassignKeyslot(token int, keyslot int) error {
	res := crypt.TokenUnassignKeyslot(device.cryptDevice, uint32(token), uint32(keyslot))
	resAnyToken := token == CRYPT_ANY_TOKEN && int(res) == token
	if res < 0 && !resAnyToken {
		return &Error{functionName: "crypt_token_assign_keyslot", code: int(res)}
	}
	return nil
}

// TokenIsAssigned gets info about token assignment to particular keyslot.
// C equivalent: crypt_token_is_assigned
func (device *Device) TokenIsAssigned(token int, keyslot int) error {
	if res := crypt.TokenIsAssigned(device.cryptDevice, uint32(token), uint32(keyslot)); res < 0 {
		return &Error{functionName: "crypt_token_is_assigned", code: int(res)}
	}
	return nil
}

// TokenStatus gets info for specific token.
// On success returns the token type as string.
// C equivalent: crypt_token_status
func (device *Device) TokenStatus(token int) (string, TokenInfo) {
	cStr := strings.CString("")
	defer strings.CFree(cStr)

	res := crypt.TokenStatus(device.cryptDevice, uint32(token), &cStr)
	tokenInfo := TokenInfo(res)
	return strings.GoString(cStr), tokenInfo
}

func ensureIntialized() error {
	if err := crypt.OpenCryptsetup(); err != nil {
		return err
	}
	if err := libc.OpenLibc(); err != nil {
		return err
	}
	return nil
}

func mustInitialize() {
	if err := ensureIntialized(); err != nil {
		panic(err)
	}
}
