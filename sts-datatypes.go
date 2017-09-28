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
	"encoding/base64"
	"encoding/xml"
	"errors"
)

// Issuer - http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
// The <Issuer> element, with complex type NameIDType, provides information
// about the issuer of a SAML assertion or protocol message.
type Issuer struct {
	XMLName xml.Name
	SAML    string `xml:"xmlns:saml,attr"`
	URL     string `xml:",innerxml"`
}

// Signature - An XML Signature that protects the integrity of and authenticates
// the issuer of the assertion
type Signature struct {
	XMLName    xml.Name
	ID         string `xml:"Id,attr"`
	SignedInfo struct {
		XMLName                xml.Name
		CanonicalizationMethod CanonicalizationMethod
		SignatureMethod        SignatureMethod
		SamlsigReference       struct {
			XMLName      xml.Name
			URI          string       `xml:"URI,attr"`
			Transforms   Transforms   `xml:",innerxml"`
			DigestMethod DigestMethod `xml:",innerxml"`
			DigestValue  DigestValue  `xml:",innerxml"`
		}
	}
	SignatureValue struct {
		XMLName xml.Name
		Value   string `xml:",innerxml"`
	}
	KeyInfo KeyInfo
}

// KeyInfo - SAML does not require the use of
// <ds:KeyInfo>, nor does it impose any restrictions
// on its use. Therefore, <ds:KeyInfo> MAY be absent.
type KeyInfo struct {
	XMLName  xml.Name
	X509Data struct {
		XMLName         xml.Name
		X509Certificate X509Certificate `xml:",innerxml"`
	} `xml:",innerxml"`
}

// CanonicalizationMethod -  Use of Exclusive Canonicalization ensures
// that signatures created over SAML messages embedded in an XML
// context can be verified independent of that context.
type CanonicalizationMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

// SignatureMethod - defines algorithm used to generate assertion signature.
type SignatureMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

// Transforms - Signatures in SAML messages SHOULD NOT contain transforms
// other than the enveloped signature transform (with the identifier
// http://www.w3.org/2000/09/xmldsig#enveloped-signature) or the exclusive
//
// Canonicalization transforms (with the identifier
// http://www.w3.org/2001/10/xml-exc-c14n# or
// http://www.w3.org/2001/10/xml-exc-c14n#WithComments).
// Verifiers of signatures MAY reject signatures that contain other
// transform algorithms as invalid. If they do not, verifiers MUST
// ensure that no content of the SAML message is excluded from the
// signature. This can be accomplished by establishing out-of-band
// agreement as to what transforms are acceptable, or by applying
// the transforms manually to the content and reverifying the result
// as consisting of the same SAML message.
type Transforms struct {
	XMLName   xml.Name
	Transform []struct {
		XMLName   xml.Name
		Algorithm string `xml:"Algorithm,attr"`
	}
}

// DigestMethod - algorithm used for generating the digest.
type DigestMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

// DigestValue - digest value.
type DigestValue struct {
	XMLName xml.Name
}

// X509Certificate - base64 encoded x.509 certificate data.
type X509Certificate struct {
	XMLName xml.Name
	Cert    string `xml:",innerxml"`
}

// Response - saml assertion response obtained after parsing
// base64 encoded SAML assertion response from identity provider.
type Response struct {
	XMLName      xml.Name
	SAMLP        string `xml:"xmlns:samlp,attr"`
	SAML         string `xml:"xmlns:saml,attr"`
	SAMLSIG      string `xml:"xmlns:samlsig,attr"`
	Destination  string `xml:"Destination,attr"`
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`

	Issuer    Issuer    `xml:"Issuer"`
	Signature Signature `xml:"Signature"`
	Status    Status    `xml:"Status"`
	// Assertion Assertion `xml:"Assertion"` Not implemented yet.

	// This is kept here for future use.
	origSAMLAssertion string
}

// Status - <Status> element contains a code representing
// the status of the activity carried out in response to
// the corresponding request.
type Status struct {
	XMLName    xml.Name
	StatusCode struct {
		XMLName xml.Name
		Value   string `xml:",attr"`
	} `xml:"StatusCode"`
}

// Assertion - contains assertions if any.
type Assertion struct {
	XMLName            xml.Name
	ID                 string `xml:"ID,attr"`
	Version            string `xml:"Version,attr"`
	XS                 string `xml:"xmlns:xs,attr"`
	XSI                string `xml:"xmlns:xsi,attr"`
	SAML               string `xml:"xmlns:saml,attr"`
	IssueInstant       string `xml:"IssueInstant,attr"`
	Issuer             Issuer `xml:"Issuer"`
	Subject            Subject
	Conditions         Conditions
	AuthnStatements    []AuthnStatement `xml:"AuthnStatement,omitempty"`
	AttributeStatement AttributeStatement
}

// AuthnContextClassRef --
type AuthnContextClassRef struct {
	XMLName   xml.Name
	SAML      string `xml:"xmlns:saml,attr"`
	Transport string `xml:",innerxml"`
}

// AuthnStatement --
type AuthnStatement struct {
	XMLName             xml.Name
	AuthnInstant        string       `xml:",attr"`
	SessionNotOnOrAfter string       `xml:",attr,omitempty"`
	SessionIndex        string       `xml:",attr,omitempty"`
	AuthnContext        AuthnContext `xml:"AuthnContext"`
}

// AuthnContext --
type AuthnContext struct {
	XMLName              xml.Name
	AuthnContextClassRef AuthnContextClassRef `xml:"AuthnContextClassRef"`
}

// Conditions --
type Conditions struct {
	XMLName              xml.Name
	NotBefore            string                `xml:",attr"`
	NotOnOrAfter         string                `xml:",attr"`
	AudienceRestrictions []AudienceRestriction `xml:"AudienceRestriction,omitempty"`
}

// AudienceRestriction --
type AudienceRestriction struct {
	XMLName   xml.Name
	Audiences []Audience `xml:"Audience"`
}

// Audience --
type Audience struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

// Subject --
type Subject struct {
	XMLName             xml.Name
	NameID              NameID
	SubjectConfirmation SubjectConfirmation
}

// SubjectConfirmation --
type SubjectConfirmation struct {
	XMLName                 xml.Name
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
}

// SubjectConfirmationData --
type SubjectConfirmationData struct {
	XMLName      xml.Name
	InResponseTo string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

// NameID --
type NameID struct {
	XMLName         xml.Name
	Format          string `xml:",attr"`
	SPNameQualifier string `xml:",attr,omitempty"`
	Value           string `xml:",innerxml"`
}

// AttributeValue --
type AttributeValue struct {
	XMLName xml.Name
	Type    string `xml:"xsi:type,attr"`
	Value   string `xml:",innerxml"`
}

// Attribute --
type Attribute struct {
	XMLName         xml.Name
	Name            string           `xml:",attr"`
	FriendlyName    string           `xml:",attr,omitempty"`
	NameFormat      string           `xml:",attr"`
	AttributeValues []AttributeValue `xml:"AttributeValue"`
}

// AttributeStatement --
type AttributeStatement struct {
	XMLName    xml.Name
	Attributes []Attribute `xml:"Attribute"`
}

// Validate - validate the saml response, this is a non-exhaustive
// check currently validates only
// - A valid SAML version
// - A valid ID
// - A valid signature value
func (r *Response) Validate() error {
	if r.Version != "2.0" {
		return errors.New("Unsupported SAML Version")
	}

	if len(r.ID) == 0 {
		return errors.New("Missing ID attribute on SAML Response")
	}

	if len(r.Signature.SignatureValue.Value) == 0 {
		return errors.New("No signature value found")
	}

	return nil
}

// ParseSAMLResponse - parses base64 encoded SAML assertion response XML.
func ParseSAMLResponse(samlAssertion string) (*Response, error) {
	response := Response{}
	bytesXML, err := base64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, err
	}

	if err = xml.Unmarshal(bytesXML, &response); err != nil {
		return nil, err
	}

	if err = response.Validate(); err != nil {
		return nil, err
	}

	// Save the original base64 encoded value.
	response.origSAMLAssertion = samlAssertion

	// Success.
	return &response, nil
}
