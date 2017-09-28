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

package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	jwtreq "github.com/dgrijalva/jwt-go/request"

	"github.com/minio/federator/pkg/credentials"
	"github.com/minio/federator/pkg/logger"
)

const (
	// Default JWT token for web handlers is one day.
	defaultJWTExpiry = 24 * time.Hour

	// Inter-node JWT token expiry is 100 years approx.
	defaultInterNodeJWTExpiry = 100 * 365 * 24 * time.Hour

	// URL JWT token expiry is one minute (might be exposed).
	defaultURLJWTExpiry = time.Minute
)

var (
	errInvalidAccessKeyID   = errors.New("The access key ID you provided does not exist in our records")
	errChangeCredNotAllowed = errors.New("Changing access key and secret key not allowed")
	errAuthentication       = errors.New("Authentication failed, check your access credentials")
	errNoAuthToken          = errors.New("JWT token missing")
)

func getURL(u *url.URL) string {
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
}

func canonicalAuth(accessKey, token string) string {
	return fmt.Sprintf("%s:%s", accessKey, token)
}

func authenticateJWT(accessKey, secretKey string, expiry time.Duration) (string, error) {
	passedCredential := credentials.Credential{
		AccessKey: accessKey,
		SecretKey: secretKey,
	}

	cred := globalServerCreds.Get(accessKey)
	if cred.IsExpired() {
		return "", errInvalidAccessKeyID
	}
	if cred.AccessKey != passedCredential.AccessKey {
		return "", errInvalidAccessKeyID
	}

	if !cred.Equal(passedCredential) {
		return "", errAuthentication
	}

	utcNow := time.Now().UTC()
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, jwtgo.StandardClaims{
		ExpiresAt: utcNow.Add(expiry).Unix(),
		IssuedAt:  utcNow.Unix(),
		Subject:   accessKey,
	})

	tokenStr, err := token.SignedString([]byte(cred.SecretKey))
	if err != nil {
		return "", err
	}

	return canonicalAuth(accessKey, tokenStr), nil
}

func authenticateURL(accessKey, secretKey string) (string, error) {
	return authenticateJWT(accessKey, secretKey, defaultURLJWTExpiry)
}

func authenticateNode(accessKey, secretKey string) (string, error) {
	return authenticateJWT(accessKey, secretKey, defaultInterNodeJWTExpiry)
}

func authenticateWeb(accessKey, secretKey string) (token string, err error) {
	return authenticateJWT(accessKey, secretKey, defaultJWTExpiry)
}

func isAuthTokenValid(tokenStr string) bool {
	token, claims, err := parseJWT(tokenStr)
	if err != nil {
		logger.ErrorIf(err, "Unable to parse JWT token string")
		return false
	}
	if err = claims.Valid(); err != nil {
		logger.ErrorIf(err, "Invalid claims in JWT token string")
		return false
	}
	return token.Valid
}

func isHTTPTokenValid(auth string) bool {
	return isAuthTokenValid(auth)
}

func isHTTPRequestValid(req *http.Request) bool {
	return webRequestAuthenticate(req) == nil
}

// Extract and parse a JWT token from an HTTP request.
// This behaves the same as Parse, but accepts a request and an extractor
// instead of a token string.  The Extractor interface allows you to define
// the logic for extracting a token.  Several useful implementations are provided.
func parseFromRequest(req *http.Request) (token *jwtgo.Token, claims jwtgo.StandardClaims, err error) {
	auth := req.Header.Get("Authorization")
	return parseJWT(auth)
}

func parseJWT(auth string) (token *jwtgo.Token, claims jwtgo.StandardClaims, err error) {
	accessKey, tokenStr := extractAccessAndJWT(auth)
	if tokenStr == "" {
		return nil, claims, jwtreq.ErrNoTokenInRequest
	}
	token, err = jwtgo.ParseWithClaims(tokenStr, &claims, func(jwtToken *jwtgo.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwtgo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", jwtToken.Header["alg"])
		}
		cred := globalServerCreds.Get(accessKey)
		if cred.IsExpired() {
			return nil, errInvalidAccessKeyID
		}
		if cred.AccessKey != accessKey {
			return nil, errInvalidAccessKeyID
		}
		return []byte(cred.SecretKey), nil
	})
	return token, claims, err
}

// Check if the request is authenticated.
// Returns nil if the request is authenticated. errNoAuthToken if token missing.
// Returns errAuthentication for all other errors.
func webRequestAuthenticate(req *http.Request) error {
	jwtToken, claims, err := parseFromRequest(req)
	if err != nil {
		if err == jwtreq.ErrNoTokenInRequest {
			return errNoAuthToken
		}
		return errAuthentication
	}
	if !jwtToken.Valid {
		return errAuthentication
	}
	if err = claims.Valid(); err != nil {
		return err
	}
	cred := globalServerCreds.Get(claims.Subject)
	if cred.IsExpired() {
		return errInvalidAccessKeyID
	}
	if cred.AccessKey != claims.Subject {
		return errInvalidAccessKeyID
	}
	return nil
}
