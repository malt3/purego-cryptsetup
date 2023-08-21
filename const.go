package cryptsetup

const (
	/** enable discards aka trim */
	CRYPT_ACTIVATE_ALLOW_DISCARDS = 0x8

	/** corruption detected (verity), output only */
	CRYPT_ACTIVATE_CORRUPTED = 0x20

	/** dm-verity: ignore_corruption flag - ignore corruption, log it only */
	CRYPT_ACTIVATE_IGNORE_CORRUPTION = 0x100

	/** ignore persistently stored flags */
	CRYPT_ACTIVATE_IGNORE_PERSISTENT = 0x4000

	/** dm-verity: ignore_zero_blocks - do not verify zero blocks */
	CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS = 0x400

	/** key loaded in kernel keyring instead directly in dm-crypt */
	CRYPT_ACTIVATE_KEYRING_KEY = 0x800

	/** dm-integrity: direct writes, do not use journal */
	CRYPT_ACTIVATE_NO_JOURNAL = 0x1000

	/** only reported for device without uuid */
	CRYPT_ACTIVATE_NO_UUID = 0x2

	/** skip global udev rules in activation ("private device"), input only */
	CRYPT_ACTIVATE_PRIVATE = 0x10

	/** device is read only */
	CRYPT_ACTIVATE_READONLY = 0x1

	/** dm-integrity: recovery mode - no journal, no integrity checks */
	CRYPT_ACTIVATE_RECOVERY = 0x2000

	/** dm-verity: restart_on_corruption flag - restart kernel on corruption */
	CRYPT_ACTIVATE_RESTART_ON_CORRUPTION = 0x200

	/** use same_cpu_crypt option for dm-crypt */
	CRYPT_ACTIVATE_SAME_CPU_CRYPT = 0x40

	/** activate even if cannot grant exclusive access (dangerous) */
	CRYPT_ACTIVATE_SHARED = 0x4

	/** use submit_from_crypt_cpus for dm-crypt */
	CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS = 0x80

	/** iterate through all keyslots and find first one that fits */
	CRYPT_ANY_SLOT = -0x1

	/** iterate through all tokens */
	CRYPT_ANY_TOKEN = -0x1
	/** lazy deactivation - remove once last user releases it */
	CRYPT_DEACTIVATE_DEFERRED = 0x1

	/** force deactivation - if the device is busy, it is replaced by error device */
	CRYPT_DEACTIVATE_FORCE = 0x2

	/** debug all */
	CRYPT_DEBUG_ALL = -0x1

	/** debug none */
	CRYPT_DEBUG_NONE = 0x0

	/** integrity dm-integrity device */
	CRYPT_INTEGRITY = "INTEGRITY"

	/** argon2i according to rfc */
	CRYPT_KDF_ARGON2I = "argon2i"

	/** argon2id according to rfc */
	CRYPT_KDF_ARGON2ID = "argon2id"

	/** pbkdf2 according to rfc2898, luks1 legacy */
	CRYPT_KDF_PBKDF2 = "pbkdf2"

	/** read key only to the first end of line (\\n). */
	CRYPT_KEYFILE_STOP_EOL = 0x1

	/** debug log level - always on stdout */
	CRYPT_LOG_DEBUG = -0x1

	/** error log level */
	CRYPT_LOG_ERROR = 0x1

	/** normal log level */
	CRYPT_LOG_NORMAL = 0x0

	/** verbose log level */
	CRYPT_LOG_VERBOSE = 0x2

	/** loop-aes compatibility mode */
	CRYPT_LOOPAES = "LOOPAES"

	/** luks version 1 header on-disk */
	CRYPT_LUKS1 = "LUKS1"

	/** luks version 2 header on-disk */
	CRYPT_LUKS2 = "LUKS2"

	/** iteration time set by crypt_set_iteration_time(), for compatibility only. */
	CRYPT_PBKDF_ITER_TIME_SET = 0x1

	/** never run benchmarks, use pre-set value or defaults. */
	CRYPT_PBKDF_NO_BENCHMARK = 0x2

	/** plain crypt device, no on-disk header */
	CRYPT_PLAIN = "PLAIN"

	/** unfinished offline reencryption */
	CRYPT_REQUIREMENT_OFFLINE_REENCRYPT = 0x1

	/** unknown requirement in header (output only) */
	CRYPT_REQUIREMENT_UNKNOWN = 0x80000000

	/** crypt_rng_random  - use /dev/random (waits if no entropy in system) */
	CRYPT_RNG_RANDOM = 0x1

	/** crypt_rng_urandom - use /dev/urandom */
	CRYPT_RNG_URANDOM = 0x0

	/** tcrypt (truecrypt-compatible and veracrypt-compatible) mode */
	CRYPT_TCRYPT = "TCRYPT"

	/** try to load backup header */
	CRYPT_TCRYPT_BACKUP_HEADER = 0x4

	/** try to load hidden header (describing hidden device) */
	CRYPT_TCRYPT_HIDDEN_HEADER = 0x2

	/** include legacy modes when scanning for header */
	CRYPT_TCRYPT_LEGACY_MODES = 0x1

	/** device contains encrypted system (with boot loader) */
	CRYPT_TCRYPT_SYSTEM_HEADER = 0x8

	/** include veracrypt modes when scanning for header,
	 *  all other tcrypt flags applies as well.
	 *  veracrypt device is reported as tcrypt type.
	 */
	CRYPT_TCRYPT_VERA_MODES = 0x10

	/** dm-verity mode */
	CRYPT_VERITY = "VERITY"

	/** verity hash in userspace before activation */
	CRYPT_VERITY_CHECK_HASH = 0x2

	/** create hash - format hash device */
	CRYPT_VERITY_CREATE_HASH = 0x4

	/** no on-disk header (only hashes) */
	CRYPT_VERITY_NO_HEADER = 0x1

	/** create keyslot with volume key not associated with current dm-crypt segment */
	CRYPT_VOLUME_KEY_NO_SEGMENT = 0x1

	/** use direct-io */
	CRYPT_WIPE_NO_DIRECT_IO = 0x1

	/**< Fill with zeroes */
	CRYPT_WIPE_ZERO = 0x0

	/**< Use RNG to fill data */
	CRYPT_WIPE_RANDOM = 0x1

	/**< Add encryption and fill with zeroes as plaintext */
	CRYPT_WIPE_ENCRYPTED_ZERO = 0x2

	/**< Compatibility only, do not use (Gutmann method) */
	CRYPT_WIPE_SPECIAL = 0x3
)

// TokenInfo is an enum type for token information.
type TokenInfo int

const (
	// token is invalid.
	CRYPT_TOKEN_INVALID = 0x0
	// token is empty (free).
	CRYPT_TOKEN_INACTIVE = 0x1
	// active internal token with driver.
	CRYPT_TOKEN_INTERNAL = 0x3
	// active internal token (reserved name) with missing token driver.
	CRYPT_TOKEN_INTERNAL_UNKNOWN = 0x3
	// active external (user defined) token with driver
	CRYPT_TOKEN_EXTERNAL = 0x4
	// active external (user defined) token with missing token driver
	CRYPT_TOKEN_EXTERNAL_UNKNOWN = 0x5
)
