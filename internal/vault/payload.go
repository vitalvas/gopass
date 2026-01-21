package vault

import (
	"encoding/json"
	"time"
)

type Payload struct {
	Data    string   `json:"d"`
	OTP     *OTP     `json:"otp,omitempty"`
	Passkey *Passkey `json:"passkey,omitempty"`
	GPGKey  *GPGKey  `json:"gpg,omitempty"`
}

type OTP struct {
	Secret string `json:"s"`
	Digits int    `json:"d,omitempty"`
	Period int    `json:"p,omitempty"`
}

type Passkey struct {
	ID            string    `json:"id"`
	PrivateKeyPEM string    `json:"priv"`
	PublicKeyPEM  string    `json:"pub"`
	RPID          string    `json:"rp"`
	UserID        string    `json:"uid"`
	UserName      string    `json:"uname"`
	SignCount     uint32    `json:"cnt"`
	CreatedAt     time.Time `json:"created"`
}

type GPGKey struct {
	KeyID       string    `json:"id"`
	Fingerprint string    `json:"fpr"`
	UserID      string    `json:"uid"`
	Email       string    `json:"email,omitempty"`
	PublicKey   string    `json:"pub"`
	PrivateKey  string    `json:"priv,omitempty"`
	CreatedAt   time.Time `json:"created"`
}

func (p *Payload) Marshal() ([]byte, error) {
	return json.Marshal(p)
}

func PayloadUnmarshal(data []byte) (*Payload, error) {
	var p = &Payload{}

	err := json.Unmarshal(data, p)
	if err != nil {
		return nil, err
	}

	return p, nil
}
