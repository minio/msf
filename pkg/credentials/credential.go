/*
 * Minio Cloud Storage, (C) 2015, 2016, 2017 Minio, Inc.
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

// Credential - container for access and secret key, also carries
// expiration which indicates when the associated acces/secret keys
// are going to be expired.
type Credential struct {
	AccessKey  string    `xml:"AccessKeyId,omitempty" json:"accessKey,omitempty"`
	SecretKey  string    `xml:"SecretAccessKey,omitempty" json:"secretKey,omitempty"`
	Expiration time.Time `xml:"Expiration,omitempty" json:"expiration,omitempty"`
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
func NewCredential() (Credential, error) {
	return NewCredentialWithExpiration(timeSentinel)
}

// NewCredentialWithExpiration returns new Credentials for the requested access key
// and secret key length. Returns an error if there was an error in generating
// credentials.Optionally expiration can be set to signify the validity of these
// generated credentials.
func NewCredentialWithExpiration(expiration time.Time) (Credential, error) {
	// Generate access key.
	keyBytes := make([]byte, accessKeyMaxLen)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return Credential{}, err
	}
	for i := 0; i < accessKeyMaxLen; i++ {
		keyBytes[i] = alphaNumericTable[keyBytes[i]%alphaNumericTableLen]
	}
	accessKey := string(keyBytes)

	// Generate secret key.
	keyBytes = make([]byte, secretKeyMaxLen)
	_, err = rand.Read(keyBytes)
	if err != nil {
		return Credential{}, err
	}
	secretKey := string([]byte(base64.StdEncoding.EncodeToString(keyBytes))[:secretKeyMaxLen])
	return Credential{
		AccessKey:  accessKey,
		SecretKey:  secretKey,
		Expiration: expiration,
	}, nil
}

var timeSentinel = time.Unix(0, 0).UTC()

// UTCNow - returns current UTC time.
func UTCNow() time.Time {
	return time.Now().UTC()
}
