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
	"os"
	"path/filepath"
	"sync"

	"github.com/minio/minio/pkg/quick"
)

type fsStore struct {
	sync.RWMutex
	Version string                `json:"version"`
	Creds   map[string]Credential `json:"creds"`
}

// Federator credentials file.
const federatorCredsFile = "creds.json"

// NewStorage - Initialize a new credetnials store.
func NewStore() Store {
	return &fsStore{
		Version: "1",
		Creds:   make(map[string]Credential),
	}
}

func (s *fsStore) Set(cred Credential) (prevCred Credential) {
	s.Lock()
	defer s.Unlock()

	prevCred = s.Creds[cred.AccessKey]

	s.Creds[cred.AccessKey] = cred

	return prevCred
}

func (s *fsStore) Get(accessKey string) Credential {
	s.RLock()
	defer s.RUnlock()

	return s.Creds[accessKey]
}

func (s *fsStore) Delete(accessKey string) (prevCred Credential) {
	s.Lock()
	defer s.Unlock()

	prevCred = s.Creds[accessKey]

	delete(s.Creds, accessKey)

	return prevCred
}

func (s *fsStore) Load() error {
	_, err := quick.Load(filepath.Join(configDir.Get(), federatorCredsFile), s)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// If creds.json doesn't exist, its okay to proceed and ignore.
	return nil
}

func (s *fsStore) Save() error {
	s.Lock()
	defer s.Unlock()
	// Purge all the expired entries before saving.
	for k, v := range s.Creds {
		if v.IsExpired() {
			delete(s.Creds, k)
		}
	}
	return quick.Save(filepath.Join(configDir.Get(), federatorCredsFile), s)
}
