package sberid_test

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/sberid"
)

func randSeq(n int) string {
	var letters = []rune("1234567890abcdef")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

//  openssl s_client -showcerts -connect open.api.sberbank.ru:443 </dev/null 2>/dev/null \
//    | sed -ne '/-BEGIN/,/-END/p' > domain.crt
func ExampleOpenApi() {
	ctx := context.TODO()
	conf := &oauth2.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		Scopes:       []string{"SCOPE1", "SCOPE2"},
		Endpoint:     sberid.EndpointOpen,
		RedirectURL:  "http://localhost/callback",
	}

	fmt.Println(conf.AuthCodeURL(
		randSeq(8),
		oauth2.SetAuthURLParam("client_type", "PRIVATE"),
		oauth2.SetAuthURLParam("nonce", randSeq(16)),
	))
	//return

	bundleCertF, err := os.Open("domain.crt")
	if err != nil {
		return
	}

	sslTransport, err := sberid.NewDomainCertTransport(bundleCertF)

	httpClient := &http.Client{
		Transport: sberid.NewTransport(sslTransport),
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	var code string = "CODE"

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("RqUID", randSeq(32)),
		oauth2.SetAuthURLParam("X-IBM-Client-Id", conf.ClientID),
	}

	tok, err := conf.Exchange(ctx, code, opts...)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(tok)

	client := conf.Client(ctx, tok)
	client.Get("...")
}

// openssl pkcs12 -in client.p12 -clcerts -nokeys -out client_cert.crt
// openssl pkcs12 -in client.p12 -nodes -nocerts -out private.key
// openssl pkcs12 -in client.p12 -cacerts -nokeys -chain -out cacerts.crt
func ExampleApiCert() {
	ctx := context.TODO()
	conf := &oauth2.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		Scopes:       []string{"SCOPE1", "SCOPE2"},
		Endpoint:     sberid.EndpointApi,
		RedirectURL:  "https://sbermarket.ru/users/auth/sberbank/callback",
	}

	fmt.Println(conf.AuthCodeURL(
		randSeq(8),
		oauth2.SetAuthURLParam("client_type", "PRIVATE"),
		oauth2.SetAuthURLParam("nonce", randSeq(16)),
	))

	certF, err := os.Open("client_cert.crt")
	if err != nil {
		return
	}
	keyF, err := os.Open("private.key")
	if err != nil {
		return
	}
	caCertF, err := os.Open("cacerts.cer")
	if err != nil {
		return
	}

	sslTransport, err := sberid.NewClientCertTransport(certF, keyF, caCertF)

	httpClient := &http.Client{
		Transport: sberid.NewTransport(sslTransport),
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	var code string = "CODE"

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("RqUID", randSeq(32)),
		oauth2.SetAuthURLParam("X-IBM-Client-Id", conf.ClientID),
	}

	tok, err := conf.Exchange(ctx, code, opts...)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(tok)

	client := conf.Client(ctx, tok)
	client.Get("...")
}
