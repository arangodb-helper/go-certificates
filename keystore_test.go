//
// DISCLAIMER
//
// Copyright 2018 ArangoDB GmbH, Cologne, Germany
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Copyright holder is ArangoDB GmbH, Cologne, Germany
//

package certificates

import (
	"bytes"
	"testing"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

func TestCreateKeystoreRoundTrip(t *testing.T) {
	caCert, caKey, err := CreateCertificate(CreateCertificateOptions{
		CommonName: "Test CA",
		IsCA:       true,
		ECDSACurve: "P256",
		ValidFor:   time.Hour,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCAFromPEM(caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := CreateCertificate(CreateCertificateOptions{
		CommonName: "localhost",
		Hosts:      []string{"localhost"},
		ECDSACurve: "P256",
		ValidFor:   time.Hour,
	}, &ca)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("secret")
	raw, err := CreateKeystore(cert, key, caCert, "server", password)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("keystore is empty")
	}

	ks := keystore.New(keystore.WithCaseExactAliases())
	if err := ks.Load(bytes.NewReader(raw), password); err != nil {
		t.Fatal(err)
	}
	entry, err := ks.GetPrivateKeyEntry("server", password)
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.PrivateKey) == 0 || len(entry.CertificateChain) == 0 {
		t.Fatalf("private key entry is incomplete: key %d bytes, chain %d", len(entry.PrivateKey), len(entry.CertificateChain))
	}
	if _, err := ks.GetTrustedCertificateEntry("testca"); err != nil {
		t.Fatal(err)
	}
}
