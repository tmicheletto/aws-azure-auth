package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"github.com/RobotsAndPencils/go-saml"
	"github.com/google/uuid"
	"time"
)

const AWS_SAML_ENDPOINT = "https://signin.aws.amazon.com/saml"

func CreateSAMLRequest(appID string) (string, error) {
	samlTemplate := `
       <samlp:AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="id%s" Version="2.0" IssueInstant="%s" IsPassive="false" AssertionConsumerServiceURL="%s" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
           <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">%s</Issuer>
           <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"></samlp:NameIDPolicy>
       </samlp:AuthnRequest>
       `
	request := fmt.Sprintf(samlTemplate, uuid.New().String(), time.Now().Format(time.RFC3339), AWS_SAML_ENDPOINT, appID)

	var b bytes.Buffer
	w, err := flate.NewWriter(&b, flate.BestSpeed)
	if err != nil {
		return "", err
	}

	w.Write([]byte(request))
	if err = w.Close(); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

func ParseRolesFromSAMLResponse(samlResponse string) ([]string, error) {
	response, err := saml.ParseEncodedResponse(samlResponse)
	if err != nil {
		return []string{}, err
	}
	return response.GetAttributeValues("https://aws.amazon.com/SAML/Attributes/Role"), nil
}