package engpo

import (
	"errors"

	"github.com/akiekano12/engpo/ecb" // Import the ECB sub-package
)

// EncryptAES encrypts plaintext using AES with the specified mode.
func EncryptAES(mode string, key, iv, plaintext []byte) ([]byte, error) {
	switch mode {
	case "ecb":
		return ecb.EncryptECB(key, plaintext)
	// Add cases for other modes (e.g., "cbc", "cfb", etc.)
	default:
		return nil, errors.New("unsupported AES mode")
	}
}

// DecryptAES decrypts ciphertext using AES with the specified mode.
func DecryptAES(mode string, key, iv, ciphertext []byte) ([]byte, error) {
	switch mode {
	case "ecb":
		return ecb.DecryptECB(key, ciphertext)
	// Add cases for other modes (e.g., "cbc", "cfb", etc.)
	default:
		return nil, errors.New("unsupported AES mode")
	}
}
