package gpgagent

import (
	"crypto/dsa" //nolint:staticcheck // Required for legacy GPG key support
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"io"
	"math/big"

	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/elgamal"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func computeKeygrip(pub *packet.PublicKey) string {
	hash := sha1.New()

	switch key := pub.PublicKey.(type) {
	case *rsa.PublicKey:
		writeCanonicalSexp(hash, "rsa", "n", key.N.Bytes(), "e", big.NewInt(int64(key.E)).Bytes())

	case *dsa.PublicKey:
		writeCanonicalSexp(hash, "dsa", "p", key.P.Bytes(), "q", key.Q.Bytes(), "g", key.G.Bytes(), "y", key.Y.Bytes())

	case *elgamal.PublicKey:
		writeCanonicalSexp(hash, "elg", "p", key.P.Bytes(), "g", key.G.Bytes(), "y", key.Y.Bytes())

	case *ecdsa.PublicKey:
		oid := getECDSAOID(key)
		point := append([]byte{0x04}, append(key.X.Bytes(), key.Y.Bytes()...)...)
		writeCanonicalSexp(hash, "ecc", "curve", oid, "q", point)

	case *eddsa.PublicKey:
		point := key.X
		writeCanonicalSexp(hash, "ecc", "curve", []byte("Ed25519"), "flags", []byte("eddsa"), "q", point)

	default:
		return fmt.Sprintf("%X", pub.Fingerprint)
	}

	return fmt.Sprintf("%X", hash.Sum(nil))
}

func writeCanonicalSexp(h io.Writer, algo string, params ...any) {
	fmt.Fprintf(h, "(%d:%s", len(algo), algo)

	for i := 0; i < len(params); i += 2 {
		name := params[i].(string)
		value := params[i+1].([]byte)

		if len(value) > 0 && value[0]&0x80 != 0 {
			newValue := make([]byte, len(value)+1)
			copy(newValue[1:], value)
			value = newValue
		}

		fmt.Fprintf(h, "(%d:%s%d:", len(name), name, len(value))
		h.Write(value)
		h.Write([]byte(")"))
	}

	h.Write([]byte(")"))
}

func getECDSAOID(key *ecdsa.PublicKey) []byte {
	curveName := key.Curve.Params().Name

	switch curveName {
	case "P-256":
		return []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	case "P-384":
		return []byte{0x2B, 0x81, 0x04, 0x00, 0x22}
	case "P-521":
		return []byte{0x2B, 0x81, 0x04, 0x00, 0x23}
	default:
		return []byte(curveName)
	}
}
