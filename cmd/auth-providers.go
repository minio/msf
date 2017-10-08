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
	"fmt"
	"sync"
)

type authProviders struct {
	sync.RWMutex
	SAML samlProvider `json:"saml"`
	// Add new auth providers.
}

const minioIAM = "arn:minio:iam:"

func (a *authProviders) GetAllAuthProviders() map[string]struct{} {
	authProviderArns := make(map[string]struct{})
	if a.SAML.Enable {
		// Construct the auth ARN.
		authARN := minioIAM + "us-east-1:1:saml"
		authProviderArns[authARN] = struct{}{}
	}
	return authProviderArns
}

func (a *authProviders) GetSAML() samlProvider {
	a.RLock()
	defer a.RUnlock()
	return a.SAML
}

type samlProvider struct {
	Enable  bool   `json:"enable"`
	IDPURL  string `json:"idp"`
	RootURL string `json:"sp"`
}

func (s samlProvider) Validate() error {
	if s.IDPURL != "" && s.RootURL != "" && s.Enable {
		return nil
	}
	return fmt.Errorf("Invalid saml provider configuration %#v", s)
}
