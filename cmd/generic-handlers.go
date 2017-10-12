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

package cmd

import (
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
)

// HandlerFunc - useful to chain different middleware http.Handler
type HandlerFunc func(http.Handler) http.Handler

func registerHandlers(h http.Handler, handlerFns ...HandlerFunc) http.Handler {
	for _, hFn := range handlerFns {
		h = hFn(h)
	}
	return h
}

type proxyHandler struct {
	handler http.Handler
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

var regCredV4 = regexp.MustCompile("Credential=([A-Z0-9]+)/")

// New creates an instance of Forwarder based on the provided list of configuration options
func authProxyDirector(req *http.Request) {
	creds := globalMFSCreds.Get(regCredV4.FindString(req.Header.Get("Authorization")))
	targetQuery := creds.Endpoint.RawQuery
	if creds.Endpoint != nil {
		req.URL.Host = creds.Endpoint.Host
		req.URL.Scheme = creds.Endpoint.Scheme
		req.URL.Path = singleJoiningSlash(creds.Endpoint.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
}

func setProxyHandler(h http.Handler) http.Handler {
	return &httputil.ReverseProxy{
		Director: authProxyDirector,
	}
}
