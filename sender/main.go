package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"github.com/alancesar/go-webhooks/pkg"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	webhookURL = "http://localhost:8080/notifications"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Enter a message: ")
		message, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalln(err)
		}

		fmt.Print("Enter the secret: ")
		secret, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalln(err)
		}
		secret = strings.ReplaceAll(secret, "\n", "")

		if err := sendNotification(message, secret); err != nil {
			fmt.Println(err)
		}

		log.Println("message sent successfully")
	}
}

func sendNotification(message, secret string) error {
	notification := pkg.NewNotification(message)
	payload, err := notification.Marshal()
	if err != nil {
		return err
	}

	body := bytes.NewReader(payload)
	request, err := http.NewRequest(http.MethodPost, webhookURL, body)
	if err != nil {
		return err
	}

	hash := hmac.New(sha256.New, []byte(secret))
	signature, err := notification.Sign(hash)
	if err != nil {
		return err
	}

	request.Header.Add(pkg.SignatureHeaderKey, signature)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	return nil
}
