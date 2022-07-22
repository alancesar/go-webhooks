package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os/signal"
	"syscall"
	"time"
)

const (
	signaturePrefix    = "sha256="
	signatureHeaderKey = "X-Signature"
	addr               = ":8080"
	secretLength       = 16
)

var (
	letterRunes        = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	signaturePrefixLen = len(signaturePrefix)
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	secret := generateSecret(secretLength)

	mux := http.NewServeMux()
	mux.HandleFunc("/notifications", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusNotFound)
			return
		}

		bytes, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		signature := request.Header.Get(signatureHeaderKey)
		if len(signature) == 0 {
			fmt.Println("message denied: signature is not present")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		if err := checkSignature(bytes, signature, secret); err != nil {
			fmt.Println("message denied: invalid signature")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		fmt.Printf("message received successfully: %s", string(bytes))
		writer.WriteHeader(http.StatusCreated)
	})

	server := http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil || !errors.Is(err, http.ErrServerClosed) {
			log.Fatalln(err)
		}
	}()

	log.Printf("running at %s\n", addr)
	log.Printf("the secret is %s\n", secret)
	<-ctx.Done()
	stop()
	log.Println("shutting down...")
}

func generateSecret(length int) string {
	rand.Seed(time.Now().UnixNano())

	b := make([]rune, length)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func checkSignature(input []byte, signature, secret string) error {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(input)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(signature[signaturePrefixLen:]), []byte(expectedMAC)) {
		return errors.New("invalid signature")
	}

	return nil
}
