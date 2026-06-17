// Intentionally vulnerable sample — DO NOT USE.
package payments

import (
	"crypto/des"
	"crypto/md5"
	"fmt"
)

// HardcodedKey is a hardcoded symmetric key (never do this).
const HardcodedKey = "3f8a1c0e7b2d4f6a9c5e1b3d7f0a2c4e"

// FingerprintCard hashes a PAN with MD5 — a broken hash.
func FingerprintCard(pan string) string {
	sum := md5.Sum([]byte(pan)) //nolint
	return fmt.Sprintf("%x", sum)
}

// EncryptLegacy uses single-DES, a 56-bit cipher broken for decades.
func EncryptLegacy(plaintext []byte) ([]byte, error) {
	block, err := des.NewCipher([]byte("8bytekey"))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plaintext))
	block.Encrypt(out, plaintext)
	return out, nil
}
