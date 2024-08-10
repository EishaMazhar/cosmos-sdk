// crypto/dilithium/dilithium_test.go
package dilithium

import (
	"testing"
)

func TestDilithiumKeyGenSignVerify(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	msg := []byte("test message")
	sig, err := key.Sign(msg)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	pubKey := key.GetPublicKey()

	valid, err := Verify(msg, sig, pubKey)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if !valid {
		t.Fatalf("signature verification failed")
	}
}
