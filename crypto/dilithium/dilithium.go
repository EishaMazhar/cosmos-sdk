// crypto/dilithium/dilithium.go
package dilithium

import (
	"errors"
	"fmt"

	"github.com/theQRL/go-qrllib/dilithium"
)

type DilithiumKey struct {
	DilithiumInstance *dilithium.Dilithium
}

// GenerateKey generates a new CRYSTALS-DILITHIUM key pair
func GenerateKey() (*DilithiumKey, error) {
	dilithiumInstance, err := dilithium.New()
	if err != nil {
		return nil, err
	}
	return &DilithiumKey{DilithiumInstance: dilithiumInstance}, nil
}

// Sign creates a CRYSTALS-DILITHIUM signature for a given message
func (key *DilithiumKey) Sign(msg []byte) ([]byte, error) {
	if key.DilithiumInstance == nil {
		return nil, errors.New("Dilithium instance not initialized")
	}

	signature, err := key.DilithiumInstance.Sign(msg)
	if err != nil {
		return nil, err
	}

	return signature[:], nil
}

// Verify checks a CRYSTALS-DILITHIUM signature
func Verify(msg, signature []byte, pubKey []byte) (bool, error) {
	var pk [dilithium.CryptoPublicKeyBytes]uint8
	copy(pk[:], pubKey[:dilithium.CryptoPublicKeyBytes])

	var sig [dilithium.CryptoBytes]uint8
	copy(sig[:], signature[:dilithium.CryptoBytes])

	return dilithium.Verify(msg, sig, &pk), nil
}

// GetPublicKey returns the public key for the Dilithium instance
func (key *DilithiumKey) GetPublicKey() []byte {
	if key.DilithiumInstance == nil {
		return nil
	}
	pk := key.DilithiumInstance.GetPK()
	return pk[:]
}

// GetPrivateKey returns the private key for the Dilithium instance
func (key *DilithiumKey) GetPrivateKey() []byte {
	if key.DilithiumInstance == nil {
		return nil
	}
	sk := key.DilithiumInstance.GetSK()
	return sk[:]
}

// Implement proto.Message interface
func (d *DilithiumKey) Reset() {
	// Reset the Dilithium instance
	d.DilithiumInstance = nil
}

func (d *DilithiumKey) String() string {
	// Return a string representation
	return fmt.Sprintf("DilithiumKey: %x", d.DilithiumInstance.GetPK())
}

func (*DilithiumKey) ProtoMessage() {}
