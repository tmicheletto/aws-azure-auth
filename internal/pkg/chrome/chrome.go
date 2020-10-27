package chrome

import (
	"aws-azure-auth/internal/pkg/saml"
	"context"
	"fmt"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/spf13/viper"
	"net/url"
)

const (
	emailElement                 = "#i0116"
	passwordElement              = "#i0118"
	submitElement                = "#idSIButton9"
	otpElement                   = "#idTxtBx_SAOTCC_OTC"
	verifyButtonSelector         = "#idSubmit_SAOTCC_Continue"
	staySignedInCheckboxSelector = "#KmsiCheckboxField"
	fieldsSelector               = "#saml_form > fieldset"
)

type Driver struct {
	ctx          context.Context
	SAMLResponse string
}

type Dispose = func()

func NewDriver() (*Driver, Dispose) {
	// // create context
	// arg1 := fmt.Sprintf("--auth-server-whitelist=%s", AZURE_AD_SSO)
	// arg2 := fmt.Sprintf("--auth-negotiate-delegate-whitelist=%s", AZURE_AD_SSO)
	// chromeargs := [2]string{arg1, arg2}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),
		chromedp.DisableGPU,
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// create context
	ctx, cancel2 := chromedp.NewContext(allocCtx)

	//ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	//defer cancel()

	driver := &Driver{
		ctx: ctx,
	}

	chromedp.ListenTarget(driver.ctx, func(ev interface{}) {
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
				driver.SAMLResponse = response["SAMLResponse"][0]
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

	disposer := func() {
		cancel()
		cancel2()
	}

	return driver, disposer
}

func (driver *Driver) Navigate() error {
	azureAppUri := fmt.Sprintf("http://%s", viper.GetString("azureAppId"))

	azureTenantId := viper.GetString("azureTenantId")

	samlRequest, err := saml.CreateSAMLRequest(azureAppUri)
	if err != nil {
		return fmt.Errorf("could not create SAML request: %v", err)
	}
	url := fmt.Sprintf("https://login.microsoftonline.com/%s/saml2?SAMLRequest=%s", azureTenantId, url.QueryEscape(samlRequest))

	return chromedp.Run(driver.ctx,
		network.Enable(),
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{{URLPattern: saml.AWS_SAML_ENDPOINT, RequestStage: "Response"}}).WithHandleAuthRequests(true),
		chromedp.Navigate(url),
		chromedp.WaitVisible(emailElement, chromedp.ByQuery))
}

func (driver *Driver) SendUsername(username string) error {
	return chromedp.Run(driver.ctx, chromedp.SendKeys(emailElement, username, chromedp.ByQuery), chromedp.Click(submitElement, chromedp.ByQuery))
}

func (driver *Driver) SendPassword(password string) error {
	return chromedp.Run(driver.ctx, chromedp.SendKeys(passwordElement, password, chromedp.ByQuery), chromedp.Submit(submitElement, chromedp.ByQuery), chromedp.WaitVisible(otpElement, chromedp.ByQuery))
}

func (driver *Driver) SendCode(code string) ([]*cdp.Node, error) {
	chromedp.Run(driver.ctx, chromedp.SendKeys(otpElement, code, chromedp.ByQuery), chromedp.Click(verifyButtonSelector, chromedp.ByQuery), chromedp.WaitVisible(staySignedInCheckboxSelector, chromedp.ByQuery), chromedp.Click(staySignedInCheckboxSelector, chromedp.ByQuery), chromedp.Submit(submitElement, chromedp.ByQuery), chromedp.WaitVisible(fieldsSelector, chromedp.ByQuery))

	acctsSelector := "#saml_form > fieldset > div.saml-account > div > div.saml-account-name"
	var accounts []*cdp.Node
	if err := chromedp.Run(driver.ctx, chromedp.Nodes(acctsSelector, &accounts)); err != nil {
		return nil, fmt.Errorf("could not get projects: %v", err)
	}
	return accounts, nil
}