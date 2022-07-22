package pkg

import (
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"time"
)

const (
	SignatureHeaderKey = "X-Signature"
	signaturePrefix    = "sha256"
)

type (
	Notification struct {
		Message   string `json:"message"`
		Timestamp int64  `json:"timestamp"`
	}
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
)

func NewNotification(message string) Notification {
	return Notification{
		Message:   message,
		Timestamp: time.Now().UnixMilli(),
	}
}

func (n Notification) Marshal() ([]byte, error) {
	return json.Marshal(&n)
}

func (n Notification) Sign(hash hash.Hash) (string, error) {
	bytes, err := n.Marshal()
	if err != nil {
		return "", err
	}

	_, _ = hash.Write(bytes)
	signature := hex.EncodeToString(hash.Sum(nil))
	return fmt.Sprintf("%s=%s", signaturePrefix, signature), nil
}

func (n Notification) Validate(hash hash.Hash, signature string) error {
	bytes, err := n.Marshal()
	if err != nil {
		return err
	}

	_, _ = hash.Write(bytes)
	expectedHash := hex.EncodeToString(hash.Sum(nil))
	if !hmac.Equal([]byte(signature), []byte(expectedHash)) {
		return ErrInvalidSignature
	}

	return nil
}
