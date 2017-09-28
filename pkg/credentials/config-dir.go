/*
 * Federator, (C) 2017 Federator, Inc.
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

	homedir "github.com/minio/go-homedir"
)

const (
	// Default federator configuration directory where below configuration files/directories are stored.
	defaultFederatorConfigDir = ".federator"

	// Directory contains below files/directories for HTTPS configuration.
	certsDir = "certs"

	// Directory contains all CA certificates other than system defaults for HTTPS.
	certsCADir = "CAs"

	// Public certificate file for HTTPS.
	publicCertFile = "public.crt"

	// Private key file for HTTPS.
	privateKeyFile = "private.key"
)

// ConfigDir - configuration directory with locking.
type ConfigDir struct {
	sync.Mutex
	dir string
}

// Set - saves given directory as configuration directory.
func (config *ConfigDir) Set(dir string) {
	config.Lock()
	defer config.Unlock()

	config.dir = dir
}

// Get - returns current configuration directory.
func (config *ConfigDir) Get() string {
	config.Lock()
	defer config.Unlock()

	return config.dir
}

func (config *ConfigDir) getCertsDir() string {
	return filepath.Join(config.Get(), certsDir)
}

// GetCADir - returns certificate CA directory.
func (config *ConfigDir) GetCADir() string {
	return filepath.Join(config.getCertsDir(), certsCADir)
}

// Create - creates configuration directory tree.
func (config *ConfigDir) Create() error {
	return os.MkdirAll(config.GetCADir(), 0700)
}

// GetPublicCertFile - returns absolute path of public.crt file.
func (config *ConfigDir) GetPublicCertFile() string {
	return filepath.Join(config.getCertsDir(), publicCertFile)
}

// GetPrivateKeyFile - returns absolute path of private.key file.
func (config *ConfigDir) GetPrivateKeyFile() string {
	return filepath.Join(config.getCertsDir(), privateKeyFile)
}

func mustGetDefaultConfigDir() string {
	homeDir, err := homedir.Dir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(homeDir, defaultFederatorConfigDir)
}

var configDir = &ConfigDir{dir: mustGetDefaultConfigDir()}

// GetCADir - returns certificate CA directory.
func GetCADir() string {
	return configDir.GetCADir()
}

// CreateConfigDir - creates configuration directory tree.
func CreateConfigDir() error {
	return configDir.Create()
}

// GetPublicCertFile - returns absolute path of public.crt file.
func GetPublicCertFile() string {
	return configDir.GetPublicCertFile()
}

// GetPrivateKeyFile - returns absolute path of private.key file.
func GetPrivateKeyFile() string {
	return configDir.GetPrivateKeyFile()
}
