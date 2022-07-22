package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/alancesar/go-webhooks/pkg"
	"log"
	"math/rand"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	addr         = ":8080"
	secretLength = 16
)

var (
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
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

		signature := request.Header.Get(pkg.SignatureHeaderKey)
		if len(signature) == 0 {
			fmt.Println("message denied: signature is not present")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		var notification pkg.Notification
		if err := json.NewDecoder(request.Body).Decode(&notification); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		hash := hmac.New(sha256.New, []byte(secret))
		_, signature, _ = strings.Cut(signature, "=")
		if err := notification.Validate(hash, signature); err != nil {
			fmt.Println("message denied: invalid signature")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		fmt.Printf("message received successfully: %s", notification.Message)
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
