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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	router "github.com/gorilla/mux"
	"github.com/minio/saml"

	"github.com/minio/federator/pkg/credentials"
)

const (
	defaultCookieMaxAge = time.Hour * 4 // 4 hrs.
	defaultCookieName   = "token"
)

// Options represents the parameters for creating a new middleware
type Options struct {
	SP             saml.ServiceProvider
	IDPMetadata    *saml.EntityDescriptor
	IDPMetadataURL url.URL
	HTTPClient     *http.Client

	// Initiates IDP initiated login.
	AllowIDPInitiated bool
}

// New creates a new SAMLMiddleware
func New(opts Options) (*SAMLMiddleware, error) {
	m := &SAMLMiddleware{
		ServiceProvider:   opts.SP,
		AllowIDPInitiated: opts.AllowIDPInitiated,
		CookieName:        defaultCookieName,
		CookieMaxAge:      defaultCookieMaxAge,
	}

	c := opts.HTTPClient
	if c == nil {
		c = http.DefaultClient
	}

	req, err := http.NewRequest("GET", opts.IDPMetadataURL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Some providers (like OneLogin) do not work properly unless the User-Agent header is specified.
	// Setting the user agent prevents the 403 Forbidden errors.
	req.Header.Set("User-Agent", globalServerUserAgent)

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d %s", resp.StatusCode, resp.Status)
	}

	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	entity := &saml.EntityDescriptor{}
	if err = xml.Unmarshal(data, entity); err != nil {
		// this comparison is ugly, but it is how the error is generated in encoding/xml
		if err.Error() != "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
			return nil, err
		}
		entities := &saml.EntitiesDescriptor{}
		if err = xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}

		err = fmt.Errorf("no entity found with IDPSSODescriptor")
		for j := range entities.EntityDescriptors {
			ed := entities.EntityDescriptors[j]
			if len(ed.IDPSSODescriptors) > 0 {
				m.ServiceProvider.IDPMetadata = &ed
				globalSAMLProvider.IDPMetadata = &ed
				return m, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}

	m.ServiceProvider.IDPMetadata = entity
	globalSAMLProvider.IDPMetadata = entity
	return m, nil
}

// registers a new SAML router.
func registerSAMLRouter(mux *router.Router) error {
	if !globalIsSSL {
		return errors.New("SAML feature cannot be registered without SSL")
	}

	keyPair, err := tls.LoadX509KeyPair(credentials.GetPublicCertFile(), credentials.GetPrivateKeyFile())
	if err != nil {
		return err
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return err
	}

	rootURL := &url.URL{}
	idpMetadataURL := &url.URL{}

	acsURL := *rootURL
	logoutURL := *rootURL
	metadataURL := *rootURL
	acsURL.Path = path.Join(minioReservedBucketPath, "/SAML2/ACS")
	logoutURL.Path = path.Join(minioReservedBucketPath, "/logout")
	metadataURL.Path = path.Join(minioReservedBucketPath, "/SAML2/Meta")

	globalSAMLProvider = saml.ServiceProvider{
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		MetadataURL: metadataURL,
		AcsURL:      acsURL,
		LogoutURL:   logoutURL,
	}

	samlSP, err := New(Options{
		SP:                globalSAMLProvider,
		IDPMetadataURL:    *idpMetadataURL,
		AllowIDPInitiated: true,
	})
	if err != nil {
		return err
	}

	// SAML router
	samlRouter := mux.NewRoute().PathPrefix(minioReservedBucketPath).Subrouter()
	samlRouter.Methods("GET").Path("/SAML2/Meta").HandlerFunc(samlSP.SAMLMetadataHandler)
	samlRouter.Methods("POST").Path("/SAML2/ACS").HandlerFunc(samlSP.AssertionConsumerHandler)
	samlRouter.Methods("GET").Path("/login").HandlerFunc(samlSP.LoginHandler)
	samlRouter.Methods("GET").Path("/logout").HandlerFunc(samlSP.LogoutHandler)
	// if globalMinioMode == globalMinioModeGatewayGCS {
	// 	samlRouter.Methods("GET").Path("/gcs-auth").HandlerFunc(samlSP.GCSAuthHandler)
	// }

	return nil
}
