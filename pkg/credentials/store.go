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

// Store represents credential storage interface of all
// the generated credentials.
type Store interface {
	// Sets a new credential to storage, returns a previous entry for the same accessKey.
	Set(cred Credential) (prevCred Credential)

	// Get fetch a saved credential for requested accessKey.
	Get(accessKey string) (cred Credential)

	// Delete a saved credential for the accessKey, returns a deleted copy of the entry.
	Delete(accessKey string) (prevCred Credential)

	// Loads all credentials from storage.
	Load() error

	// Saves all credentials to storage.
	Save() error
}
