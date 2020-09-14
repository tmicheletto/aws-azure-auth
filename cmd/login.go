package cmd

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/RobotsAndPencils/go-saml"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const AZURE_AD_SSO = "autologon.microsoftazuread-sso.com"
const AWS_SAML_ENDPOINT = "https://signin.aws.amazon.com/saml"
const AWS_CREDENTIALS_FILE_NAME = "my-credentials"

func init() {
	rootCmd.AddCommand(loginCmd)
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login in to AWS",
	Long:  `All software has versions. This is Hugo's`,
	RunE:  execute,
}

type CredentialsProvider struct {
	*sts.Credentials
}

func (s CredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if s.Credentials == nil {
		return aws.Credentials{}, errors.New("sts credentials are nil")
	}

	return aws.Credentials{
		AccessKeyID:     aws.StringValue(s.AccessKeyId),
		SecretAccessKey: aws.StringValue(s.SecretAccessKey),
		SessionToken:    aws.StringValue(s.SessionToken),
		Expires:         aws.TimeValue(s.Expiration),
	}, nil
}

func execute(cmd *cobra.Command, args []string) error {
	// // create context
	// arg1 := fmt.Sprintf("--auth-server-whitelist=%s", AZURE_AD_SSO)
	// arg2 := fmt.Sprintf("--auth-negotiate-delegate-whitelist=%s", AZURE_AD_SSO)
	// chromeargs := [2]string{arg1, arg2}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),
		chromedp.DisableGPU,
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// create context
	ctx, cancel2 := chromedp.NewContext(allocCtx)
	defer cancel2()

	//ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	//defer cancel()

	var samlResponse string

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch evnt := ev.(type) {
		case *fetch.EventRequestPaused:
			go func(evt *fetch.EventRequestPaused) {
				nctx := chromedp.FromContext(ctx)
				lctx := cdp.WithExecutor(ctx, nctx.Target)
				requestId := evt.RequestID
				response, err := url.ParseQuery(evt.Request.PostData)
				if err != nil {
					fmt.Printf("Error parsing SAML response: %v\n", err)
					return
				}
				samlResponse = response["SAMLResponse"][0]
				defer func() {
					//err := fetch.FulfillRequest(requestId, 200).WithResponseHeaders([]*fetch.HeaderEntry{ { Name: "Content-Type", Value: "text/plain"} }).WithBody("").Do(lctx)
					err := fetch.ContinueRequest(requestId).Do(lctx)
					if err != nil {
						fmt.Println("Error with continuerequest," + err.Error())
					}
				}()
			}(evnt)
		}
	})

	azureAppUri := fmt.Sprintf("http://%s", viper.GetString("azureAppId"))
	fmt.Println(azureAppUri)
	azureTenantId := viper.GetString("azureTenantId")
	fmt.Println(azureTenantId)

	azureADUserName := viper.GetString("azureADUserName")
	fmt.Println(azureADUserName)

	url, err := createSAMLRequest(azureAppUri, azureTenantId)
	if err != nil {
		return fmt.Errorf("could not create SAML request: %v", err)
	}

	// navigate
	emailElement := "#i0116"
	passwordElement := "#i0118"
	submitElement := "#idSIButton9"
	otpElement := "#idTxtBx_SAOTCC_OTC"
	verifyButtonSelector := "#idSubmit_SAOTCC_Continue"
	staySignedInCheckboxSelector := "#KmsiCheckboxField"
	fieldsSelector := "#saml_form > fieldset"

	if err := chromedp.Run(ctx,
		network.Enable(),
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{{URLPattern: AWS_SAML_ENDPOINT, RequestStage: "Response"}}).WithHandleAuthRequests(true),
		chromedp.Navigate(url),
		chromedp.WaitVisible(emailElement, chromedp.ByQuery)); err != nil {
		return err
	}

	userName, err := prompt(fmt.Sprintf("Enter your AD user name or press enter to use default username (%s)", azureADUserName))
	if err != nil {
		return err
	}

	if len(userName) == 0 {
		fmt.Printf("Using default username %s\n", azureADUserName)
		userName = azureADUserName
	}

	if err = chromedp.Run(ctx, chromedp.SendKeys(emailElement, userName, chromedp.ByQuery), chromedp.Click(submitElement, chromedp.ByQuery)); err != nil {
		return err
	}

	password, err := prompt("Enter your password")
	if err != nil {
		return err
	}

	if err = chromedp.Run(ctx, chromedp.SendKeys(passwordElement, password, chromedp.ByQuery), chromedp.Submit(submitElement, chromedp.ByQuery), chromedp.WaitVisible(otpElement, chromedp.ByQuery)); err != nil {
		return err
	}

	code, err := prompt("Enter the code sent to your device")
	if err != nil {
		return err
	}

	if err = chromedp.Run(ctx, chromedp.SendKeys(otpElement, code, chromedp.ByQuery), chromedp.Click(verifyButtonSelector, chromedp.ByQuery), chromedp.WaitVisible(staySignedInCheckboxSelector, chromedp.ByQuery), chromedp.Click(staySignedInCheckboxSelector, chromedp.ByQuery) , chromedp.Submit(submitElement, chromedp.ByQuery), chromedp.WaitVisible(fieldsSelector, chromedp.ByQuery)); err != nil {
		return err
	}

	response, err := saml.ParseEncodedResponse(samlResponse)
	if err != nil {
		return err
	}

	roles := response.GetAttributeValues("https://aws.amazon.com/SAML/Attributes/Role")

	for i, role := range roles {
		tokens := strings.Split(role, ",")
		roleArn := tokens[0]
		fmt.Printf("%d. %s\n", i, roleArn)
	}

	answer, err := prompt("Please enter the number of the role you want to assume")
	if err != nil {
		return err
	}
	roleIdx, err := strconv.Atoi(answer)
	if err != nil {
		return err
	}

	config, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return err
	}

	// assume role
	svc := sts.New(config)
	input := parseRole(roles[roleIdx], samlResponse)
	out, err := svc.AssumeRoleWithSAMLRequest(input).Send(context.TODO())
	if err != nil {
		return err
	}
	fmt.Printf("Successfully assumed role %s. Writing credentials...\n", *input.RoleArn)
	return writeCredentials(out.Credentials)
}

func createSAMLRequest(appID string, tenantID string) (string, error) {
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

	encodedRequest := url.QueryEscape(base64.StdEncoding.EncodeToString(b.Bytes()))
	encodeUrl := fmt.Sprintf("https://login.microsoftonline.com/%s/saml2?SAMLRequest=%s", tenantID, encodedRequest)

	return encodeUrl, nil
}

func writeCredentials(creds *sts.Credentials) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	credsFile := path.Join(homeDir, ".aws", AWS_CREDENTIALS_FILE_NAME)
	if err := touchFile(credsFile); err != nil {
		return err
	}

	awsConfig := viper.New()
	awsConfig.SetConfigName(AWS_CREDENTIALS_FILE_NAME) // name of config file (without extension)
	awsConfig.SetConfigType("toml") // REQUIRED if the config file does not have the extension in the name
	awsConfig.AddConfigPath(path.Join(homeDir, ".aws"))  // call multiple times to add many search paths
	if err := awsConfig.ReadInConfig(); err != nil {
		return err
	}

	awsConfig.Set("MyCreds.aws_access_key_id", *creds.AccessKeyId)
	awsConfig.Set("MyCreds.aws_secret_access_key", *creds.SecretAccessKey)

	if err := awsConfig.WriteConfig(); err != nil {
		return err
	}
	return nil
}

func touchFile(path string) error {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		defer file.Close()
	}
	return nil
}

func prompt(question string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%v: ", question)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return answer, err
	}
	return strings.TrimSpace(answer), nil
}

func parseRole (role string, samlAssertion string) *sts.AssumeRoleWithSAMLInput {
	tokens := strings.Split(role, ",")

	return &sts.AssumeRoleWithSAMLInput{
		RoleArn: aws.String(tokens[0]),
		PrincipalArn: aws.String(tokens[1]),
		SAMLAssertion: aws.String(samlAssertion),
		DurationSeconds: aws.Int64(2400),
	}
}
