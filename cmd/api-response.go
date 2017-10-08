package cmd

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"
)

// mimeType represents various MIME type used API responses.
type mimeType string

const (
	// Means no response type.
	mimeNone mimeType = ""
	// Means response type is XML.
	mimeXML mimeType = "application/xml"
)

// Returns a hexadecimal representation of time at the
// time response is sent to the client.
func mustGetRequestID(t time.Time) string {
	return fmt.Sprintf("%X", t.UnixNano())
}

const (
	// Response request id.
	responseRequestIDKey = "x-amz-request-id"
)

// Write http common headers
func setCommonHeaders(w http.ResponseWriter) {
	// Set unique request ID for each reply.
	w.Header().Set(responseRequestIDKey, mustGetRequestID(time.Now().UTC()))
	w.Header().Set("Server", globalServerUserAgent)
	w.Header().Set("Accept-Ranges", "bytes")
}

// Encodes the response headers into XML format.
func encodeResponse(response interface{}) []byte {
	var bytesBuffer bytes.Buffer
	bytesBuffer.WriteString(xml.Header)
	e := xml.NewEncoder(&bytesBuffer)
	e.Encode(response)
	return bytesBuffer.Bytes()
}

// writeSuccessResponseXML writes success headers and response if any,
// with content-type set to `application/xml`.
func writeSuccessResponseXML(w http.ResponseWriter, response []byte) {
	writeResponse(w, http.StatusOK, response, mimeXML)
}

func writeResponse(w http.ResponseWriter, statusCode int, response []byte, mType mimeType) {
	setCommonHeaders(w)
	if mType != mimeNone {
		w.Header().Set("Content-Type", string(mType))
	}
	w.WriteHeader(statusCode)
	if response != nil {
		w.Write(response)
		w.(http.Flusher).Flush()
	}
}

// writeSTSErrorRespone writes error headers
func writeSTSErrorResponse(w http.ResponseWriter, errorCode STSErrorCode) {
	stsError := getSTSError(errorCode)
	// Generate error response.
	stsErrorResponse := getSTSErrorResponse(stsError)
	encodedErrorResponse := encodeResponse(stsErrorResponse)
	writeResponse(w, stsError.HTTPStatusCode, encodedErrorResponse, mimeXML)
}
