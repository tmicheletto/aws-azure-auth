package cmd

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"net/url"
	"strings"
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
		switch ev := ev.(type) {
		case *network.EventRequestWillBeSent:
			if strings.Contains(ev.Request.URL, "saml") {
				fmt.Printf("Event type: %s\n", ev.Type.String())
				fmt.Printf("Request Url: %v\n", ev.Request.URL)
			}
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
	//chromedp.Submit(email)
	if err := chromedp.Run(ctx, chromedp.Navigate(url),
		chromedp.WaitVisible("html > body"),
		chromedp.SendKeys(emailElement, azureADUserName),
		chromedp.Click(submitElement, chromedp.NodeVisible),
		chromedp.Sleep(time.Second * 5),
		chromedp.SendKeys(passwordElement, azureADPassword),
		chromedp.Click(submitElement, chromedp.NodeVisible),
		chromedp.Sleep(time.Second * 5),
		chromedp.Click(submitElement, chromedp.NodeVisible),
		chromedp.Sleep(time.Second * 10),
		chromedp.Click(`//*[@id="12"]/div/label`),
		chromedp.Sleep(time.Second * 10),
		chromedp.Click(`//*[@id="signin_button"]`),
		chromedp.Tasks{
			chromedp.ActionFunc(func(context context.Context) error {
				network.Enable().Do(context)
				return nil
			}),
		},
		chromedp.Sleep(time.Minute)); err != nil {
		return fmt.Errorf("could not navigate to azure: %v", err)
	}

	return nil
}

type NavigationState struct {
	currentPage string
	currentFrameID string
	pageLoaded bool
}

func (n *NavigationState) SetPageNavigated(page string, frameId string) {
	n.currentPage = page
	n.currentFrameID = frameId
	n.pageLoaded = false
}

func (n *NavigationState) SetPageLoaded(frameId string) error {
	if n.currentFrameID != frameId {
		return errors.New(fmt.Sprintf("invalid frame Id. Current: %s", n.currentFrameID))
	}
	n.pageLoaded = true
	return nil
}

func (n *NavigationState) CurrentPage() string {
	return n.currentPage
}

var pageState NavigationState
var pageChan = make(chan string)

func InterceptEvents(ev interface{}) {

	if e, ok := ev.(*page.EventFrameNavigated); ok {
		url := e.Frame.URL
		frameId := e.Frame.ID.String()

		log.Printf("[URL] %s. frame id: %s", url, frameId)
		pageState.SetPageNavigated(url, frameId)
		return
	}

	spew.Dump(ev)

	if e, ok := ev.(*page.EventFrameStoppedLoading); ok {

		log.Printf("[EVENT LOAD] Current page state: %v", pageState)
		frameId := e.FrameID.String()

		err := pageState.SetPageLoaded(frameId)
		if err != nil {
			log.Fatal(err)
		}

		currentPage := pageState.CurrentPage()
		log.Printf("[PAGE LOADED] %s", currentPage)

		pageChan <-currentPage
		return
	}
	return
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


// projectDesc contains a url, description for a project.
type projectDesc struct {
	URL, Description string
}
