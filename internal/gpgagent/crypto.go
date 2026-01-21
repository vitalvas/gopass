package gpgagent

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func LoadEntityFromArmor(armoredKey string) (*openpgp.Entity, error) {
	block, err := armor.Decode(strings.NewReader(armoredKey))
	if err != nil {
		return nil, fmt.Errorf("failed to decode armor: %w", err)
	}

	entities, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read key ring: %w", err)
	}

	if len(entities) == 0 {
		return nil, fmt.Errorf("no entities found in key")
	}

	return entities[0], nil
}

func Encrypt(publicKeyArmor string, data []byte, armored bool) ([]byte, error) {
	entity, err := LoadEntityFromArmor(publicKeyArmor)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	var output io.WriteCloser

	if armored {
		output, err = armor.Encode(&buf, "PGP MESSAGE", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create armor encoder: %w", err)
		}
	} else {
		output = nopCloser{&buf}
	}

	writer, err := openpgp.Encrypt(output, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypt writer: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close writer: %w", err)
	}

	if err := output.Close(); err != nil {
		return nil, fmt.Errorf("failed to close output: %w", err)
	}

	return buf.Bytes(), nil
}

func Decrypt(privateKeyArmor string, data []byte) ([]byte, error) {
	entity, err := LoadEntityFromArmor(privateKeyArmor)
	if err != nil {
		return nil, err
	}

	if entity.PrivateKey == nil {
		return nil, fmt.Errorf("no private key found")
	}

	entityList := openpgp.EntityList{entity}

	var reader io.Reader = bytes.NewReader(data)

	block, err := armor.Decode(reader)
	if err == nil {
		reader = block.Body
	} else {
		reader = bytes.NewReader(data)
	}

	md, err := openpgp.ReadMessage(reader, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read plaintext: %w", err)
	}

	return plaintext, nil
}

func Sign(privateKeyArmor string, data []byte, armored bool) ([]byte, error) {
	entity, err := LoadEntityFromArmor(privateKeyArmor)
	if err != nil {
		return nil, err
	}

	if entity.PrivateKey == nil {
		return nil, fmt.Errorf("no private key found")
	}

	var buf bytes.Buffer
	var output io.Writer

	if armored {
		armorWriter, err := armor.Encode(&buf, "PGP SIGNATURE", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create armor encoder: %w", err)
		}

		defer armorWriter.Close()

		output = armorWriter
	} else {
		output = &buf
	}

	err = openpgp.DetachSign(output, entity, bytes.NewReader(data), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	if armored {
		if closer, ok := output.(io.Closer); ok {
			closer.Close()
		}
	}

	return buf.Bytes(), nil
}

func SignClear(privateKeyArmor string, data []byte) ([]byte, error) {
	entity, err := LoadEntityFromArmor(privateKeyArmor)
	if err != nil {
		return nil, err
	}

	if entity.PrivateKey == nil {
		return nil, fmt.Errorf("no private key found")
	}

	var buf bytes.Buffer

	writer, err := openpgp.Sign(&buf, entity, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create sign writer: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close writer: %w", err)
	}

	return buf.Bytes(), nil
}

func Verify(publicKeyArmor string, data, signature []byte) error {
	entity, err := LoadEntityFromArmor(publicKeyArmor)
	if err != nil {
		return err
	}

	entityList := openpgp.EntityList{entity}

	var sigReader io.Reader = bytes.NewReader(signature)

	block, err := armor.Decode(sigReader)
	if err == nil {
		sigReader = block.Body
	} else {
		sigReader = bytes.NewReader(signature)
	}

	_, err = openpgp.CheckDetachedSignature(entityList, bytes.NewReader(data), sigReader, nil)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error {
	return nil
}
