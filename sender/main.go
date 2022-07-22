package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	webhookURL         = "http://localhost:8080/notifications"
	signatureHeaderKey = "X-Signature"
	signaturePrefix    = "sha256"
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
	body := strings.NewReader(message)
	request, err := http.NewRequest(http.MethodPost, webhookURL, body)
	if err != nil {
		return err
	}
	signature := generateSignature(message, secret)
	request.Header.Add(signatureHeaderKey, signature)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	return nil
}

func generateSignature(message, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(message))
	signature := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s=%s", signaturePrefix, signature)
}
