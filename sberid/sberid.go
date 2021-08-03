package sberid

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// EndpointOpen for server cert https://developer.sberbank.ru/doc/v1/sberbank-id/onetls
var EndpointOpen = oauth2.Endpoint{
	AuthURL:   "https://online.sberbank.ru/CSAFront/oidc/sberbank_id/authorize.do",
	TokenURL:  "https://open.api.sberbank.ru/ru/prod/tokens/v2/oidc",
	AuthStyle: oauth2.AuthStyleInParams,
}

// EndpointApi for server+client cert https://developer.sberbank.ru/doc/v1/sberbank-id/cert
var EndpointApi = oauth2.Endpoint{
	AuthURL:   "https://online.sberbank.ru/CSAFront/oidc/sberbank_id/authorize.do",
	TokenURL:  "https://api.sberbank.ru/ru/prod/tokens/v2/oidc",
	AuthStyle: oauth2.AuthStyleInParams,
}

// EndpointSec for VPN+server+client cert (sber ecosystem) https://developer.sberbank.ru/doc/v1/sberbank-id/fpsu
var EndpointSec = oauth2.Endpoint{
	AuthURL:   "https://online.sberbank.ru/CSAFront/oidc/sberbank_id/authorize.do",
	TokenURL:  "https://sec.sberbank.ru/ru/prod/tokens/v2/oidc",
	AuthStyle: oauth2.AuthStyleInParams,
}

var EndpointDev = oauth2.Endpoint{
	AuthURL:   "https://online.sberbank.ru/CSAFront/oidc/sberbank_id/authorize.do",
	TokenURL:  "https://dev.api.sberbank.ru/ru/prod/tokens/v2/oidc",
	AuthStyle: oauth2.AuthStyleInParams,
}

type transport struct {
	original http.RoundTripper
}

func NewTransport(original http.RoundTripper) http.RoundTripper {
	if original == nil {
		original = http.DefaultTransport
	}
	return &transport{original: original}
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.ParseForm(); err != nil {
		return nil, err
	}

	req.Header.Set("RqUID", req.Form.Get("RqUID"))
	req.Form.Del("RqUID")

	req.Header.Set("X-IBM-Client-Id", req.Form.Get("X-IBM-Client-Id"))
	req.Form.Del("X-IBM-Client-Id")

	req.Body = ioutil.NopCloser(strings.NewReader(req.Form.Encode()))
	req.ContentLength = int64(len(req.Form.Encode()))

	return t.original.RoundTrip(req)
}

func NewClientCertTransport(certReader, keyReader, caCertReader io.ReadCloser) (http.RoundTripper, error) {
	certData, err := ioutil.ReadAll(certReader)
	if err != nil {
		return nil, err
	}

	keyData, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, err
	}

	var caCertData []byte
	if caCertReader != nil {
		caCertData, err = ioutil.ReadAll(caCertReader)
		if err != nil {
			return nil, err
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
	}

	if len(caCertData) > 0 {
		pool := x509.NewCertPool()
		if err != nil {
			return nil, err
		}
		pool.AppendCertsFromPEM(caCertData)
		tr.TLSClientConfig.ClientCAs = pool
	}

	return tr, nil
}

func NewDomainCertTransport(bundleCertReader io.ReadCloser) (http.RoundTripper, error) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: x509.NewCertPool(),
		},
	}

	bundleCertData, err := ioutil.ReadAll(bundleCertReader)
	if err != nil {
		return nil, err
	}
	tr.TLSClientConfig.RootCAs.AppendCertsFromPEM(bundleCertData)

	return tr, nil
}
