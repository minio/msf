/*
 * Minio Cloud Storage, (C) 2015 Minio, Inc.
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
	"encoding/xml"
	"net/http"
)

// STSError structure
type STSError struct {
	Code           string
	Description    string
	HTTPStatusCode int
}

// STSErrorResponse - error response format
type STSErrorResponse struct {
	XMLName   xml.Name `xml:"ErrorResponse" json:"-"`
	Code      string
	Message   string
	RequestID string `xml:"RequestId"`
	HostID    string `xml:"HostId"`
}

// STSErrorCode type of error status.
type STSErrorCode int

// Error codes, non exhaustive list - http://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
const (
	ErrSTSNone STSErrorCode = iota
	ErrSTSExpiredToken
	ErrSTSIDPRejectedClaim
	ErrSTSInvalidIdentityToken
	ErrSTSMalformedPolicyDocument
	ErrSTSInternalError
)

// error code to STSError structure, these fields carry respective
// descriptions for all the error responses.
var stsErrCodeResponse = map[STSErrorCode]STSError{
	ErrSTSExpiredToken: {
		Code:           "ExpiredToken",
		Description:    "The web identity token that was passed is expired or is not valid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrSTSIDPRejectedClaim: {
		Code:           "IDPRejectedClaim",
		Description:    "The identity provider (IdP) reported that authentication failed.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrSTSInvalidIdentityToken: {
		Code:           "InvalidIdentityToken",
		Description:    "The web identity token that was passed could not be validated by AWS.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrSTSMalformedPolicyDocument: {
		Code:           "MalformedPolicyDocument",
		Description:    "The request was rejected because the policy document was malformed.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrSTSInternalError: {
		Code:           "InternalError",
		Description:    "We encountered an internal error, please try again.",
		HTTPStatusCode: http.StatusInternalServerError,
	},
}

// getSTSError provides STS Error for input STS error code.
func getSTSError(code STSErrorCode) STSError {
	return stsErrCodeResponse[code]
}

// getErrorResponse gets in standard error and resource value and
// provides a encodable populated response values
func getSTSErrorResponse(err STSError) STSErrorResponse {
	return STSErrorResponse{
		Code:      err.Code,
		Message:   err.Description,
		RequestID: "3L137",
		HostID:    "3L137",
	}
}
