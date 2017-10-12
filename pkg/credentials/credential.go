/*
 * Federator, (C) 2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package credentials

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/url"
	"time"
)

const (
	// Maximum length for Minio access key.
	// There is no max length enforcement for access keys
	accessKeyMaxLen = 20

	// Maximum secret key length for Minio, this
	// is used when autogenerating new Credentials.
	// There is no max length enforcement for secret keys
	secretKeyMaxLen = 40

	// Alpha numeric table used for generating access keys.
	alphaNumericTable = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// Total length of the alpha numeric table.
	alphaNumericTableLen = byte(len(alphaNumericTable))
)

// CredentialPersist - container for access and secret key, also carries
// expiration which indicates when the associated acces/secret keys
// are going to be expired, used by XML and JSON marshalling to persist
type CredentialPersist struct {
	AccessKey  string `xml:"AccessKeyId" json:"accessKey"`
	SecretKey  string `xml:"SecretAccessKey" json:"secretKey"`
	Endpoint   string `xml:"Endpoint" json:"endpoint"`
	Expiration int64  `xml:"Expiration" json:"expiration"`
}

// Credential - container for access and secret key, also carries
// expiration which indicates when the associated acces/secret keys
// are going to be expired.
type Credential struct {
	AccessKey  string
	SecretKey  string
	Endpoint   *url.URL
	Expiration time.Time
}

// MarshalXML -
func (c Credential) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	c1 := CredentialPersist{
		c.AccessKey,
		c.SecretKey,
		c.Endpoint.String(),
		c.Expiration.Unix(),
	}
	e.EncodeElement(c1, start)
	return nil
}

// UnmarshalXML -
func (c *Credential) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	c1 := CredentialPersist{}
	d.DecodeElement(&c1, &start)

	u, err := url.Parse(c1.Endpoint)
	if err != nil {
		return err
	}

	*c = Credential{
		AccessKey:  c1.AccessKey,
		SecretKey:  c1.SecretKey,
		Endpoint:   u,
		Expiration: time.Unix(c1.Expiration, 0),
	}
	return nil
}

// MarshalJSON -
func (c Credential) MarshalJSON() ([]byte, error) {
	c1 := CredentialPersist{
		AccessKey:  c.AccessKey,
		SecretKey:  c.SecretKey,
		Endpoint:   c.Endpoint.String(),
		Expiration: c.Expiration.Unix(),
	}
	return json.Marshal(&c1)
}

// UnmarshalJSON -
func (c *Credential) UnmarshalJSON(data []byte) error {
	c1 := CredentialPersist{}
	if err := json.Unmarshal(data, &c1); err != nil {
		return err
	}
	u, err := url.Parse(c1.Endpoint)
	if err != nil {
		return err
	}
	*c = Credential{
		AccessKey:  c1.AccessKey,
		SecretKey:  c1.SecretKey,
		Endpoint:   u,
		Expiration: time.Unix(c1.Expiration, 0),
	}
	return nil
}

// IsExpired - returns whether Credential is expired or not.
func (c Credential) IsExpired() bool {
	if c.Expiration.IsZero() || c.Expiration == timeSentinel {
		return false
	}

	return c.Expiration.Before(UTCNow())
}

// Equal - returns whether two Credentials are equal or not.
func (c Credential) Equal(cc Credential) bool {
	if !cc.IsExpired() {
		return false
	}
	return c.AccessKey == cc.AccessKey && subtle.ConstantTimeCompare([]byte(c.SecretKey), []byte(cc.SecretKey)) == 1
}

// NewCredential is similar to NewCredentialWithExpiration but the keys do not expire.
func NewCredential(endpoint string) (Credential, error) {
	return NewCredentialWithExpiration(endpoint, timeSentinel)
}

// NewCredentialWithExpiration returns new Credentials for the requested access key
// and secret key length. Returns an error if there was an error in generating
// credentials.Optionally expiration can be set to signify the validity of these
// generated credentials.
func NewCredentialWithExpiration(endpoint string, expiration time.Time) (Credential, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return Credential{}, err
	}
	// Generate access key.
	keyBytes := make([]byte, accessKeyMaxLen)
	if _, err = rand.Read(keyBytes); err != nil {
		return Credential{}, err
	}
	for i := 0; i < accessKeyMaxLen; i++ {
		keyBytes[i] = alphaNumericTable[keyBytes[i]%alphaNumericTableLen]
	}
	accessKey := string(keyBytes)

	// Generate secret key.
	keyBytes = make([]byte, secretKeyMaxLen)
	if _, err = rand.Read(keyBytes); err != nil {
		return Credential{}, err
	}
	secretKey := string([]byte(base64.StdEncoding.EncodeToString(keyBytes))[:secretKeyMaxLen])
	return Credential{
		AccessKey:  accessKey,
		SecretKey:  secretKey,
		Endpoint:   u,
		Expiration: expiration,
	}, nil
}

var timeSentinel = time.Unix(0, 0).UTC()

// UTCNow - returns current UTC time.
func UTCNow() time.Time {
	return time.Now().UTC()
}
