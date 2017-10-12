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
	"crypto/tls"
	"crypto/x509"
	"os"
	"runtime"
	"time"

	"github.com/minio/mfs/pkg/credentials"
	miniohttp "github.com/minio/minio/pkg/http"
)

var (
	// Minio mfs user agent string.
	globalMFSUserAgent = "Federator/" + ReleaseTag + " (" + runtime.GOOS + "; " + runtime.GOARCH + ")"

	// Global MFS creds.
	globalMFSCreds credentials.Store

	// CA root certificates, a nil value means system certs pool will be used
	globalRootCAs *x509.CertPool

	// IsSSL indicates if the server is configured with SSL.
	globalIsSSL bool

	globalTLSCertificate *tls.Certificate
	globalPublicCerts    []*x509.Certificate

	globalHTTPServer        *miniohttp.Server
	globalHTTPServerErrorCh = make(chan error)
	globalOSSignalCh        = make(chan os.Signal, 1)

	// Default Read/Write timeouts for each connection.
	globalConnReadTimeout  = 15 * time.Minute // Timeout after 15 minutes of no data sent by the client.
	globalConnWriteTimeout = 15 * time.Minute // Timeout after 15 minutes if no data received by the client.
)
