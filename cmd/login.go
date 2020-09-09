package cmd

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"net/url"
	"time"
)

const AZURE_AD_SSO = "autologon.microsoftazuread-sso.com"
const AWS_SAML_ENDPOINT = "https://signin.aws.amazon.com/saml"

func init() {
	rootCmd.AddCommand(loginCmd)
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login in to AWS",
	Long:  `All software has versions. This is Hugo's`,
	RunE:  execute,
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
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	//ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	//defer cancel()

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch evnt := ev.(type) {
		case *fetch.EventRequestPaused:
			go func(evt *fetch.EventRequestPaused) {
				nctx := chromedp.FromContext(ctx)
				lctx := cdp.WithExecutor(ctx, nctx.Target)
				requestId := evt.RequestID
				//body, err := fetch.GetResponseBody(requestId).Do(lctx)
				//if err != nil {
				//	log.Println(" Statuscode:" + strconv.Itoa(int(evt.ResponseStatusCode)) + "fail to get the response body " + err.Error())
				//}
				fmt.Printf("Url: :%s, RequestID: %s, Data: %s\n", evt.Request.URL, requestId, evt.Request.PostData)
				defer func() {
					err := fetch.FulfillRequest(requestId, 200).WithResponseHeaders([]*fetch.HeaderEntry{ { Name: "Content-Type", Value: "text/plain"} }).WithBody("").Do(lctx)
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

	azureADPassword := viper.GetString("azureADPassword")
	fmt.Println(azureADPassword)

	url, err := createSAMLRequest(azureAppUri, azureTenantId)
	if err != nil {
		return fmt.Errorf("could not create SAML request: %v", err)
	}

	// navigate
	emailElement := `//input[@type="email"]`
	passwordElement := `//input[@type="password"]`
	submitElement := `//input[@type="submit"]`

	if err := chromedp.Run(ctx,
		network.Enable(),
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{{URLPattern: AWS_SAML_ENDPOINT, RequestStage: "Response"}}).WithHandleAuthRequests(true),
		chromedp.Navigate(url),
		chromedp.WaitVisible("html > body"),
		chromedp.SendKeys(emailElement, azureADUserName),
		chromedp.Click(submitElement, chromedp.NodeVisible),
		chromedp.Sleep(time.Second*5),
		chromedp.SendKeys(passwordElement, azureADPassword),
		chromedp.Click(submitElement, chromedp.NodeVisible),
		chromedp.Sleep(time.Second*5),
		chromedp.Click(submitElement, chromedp.NodeVisible),
		chromedp.Sleep(time.Second*10),
		chromedp.Click(`//*[@id="12"]/div/label`),
		chromedp.Sleep(time.Second*10),
		chromedp.Click(`//*[@id="signin_button"]`),
		chromedp.Sleep(time.Minute)); err != nil {
		return fmt.Errorf("could not navigate to azure: %v", err)
	}

	return nil
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
