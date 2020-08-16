package cmd

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"github.com/spf13/cobra"
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

	// ctx, cancel := chromedp.NewContext(context.Background(), func(ctx Context) {
	// 	ctx
	// })
	// defer cancel()

	// err := chromedp.Run(ctx, chromedp.Navigate(AZURE_AD_SSO))
	// if err != nil {
	// 	return fmt.Errorf("could not navigate to aws saml endpoint: %v", err)
	// }
	// return nil

	// create context
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// list awesome go projects for the "Selenium and browser control tools."
	res, err := listAwesomeGoProjects(ctx, "Selenium and browser control tools.")
	if err != nil {
		return err
	}

	// output the values
	for k, v := range res {
		log.Printf("project %s (%s): '%s'", k, v.URL, v.Description)
	}
	return nil
}

// projectDesc contains a url, description for a project.
type projectDesc struct {
	URL, Description string
}

// listAwesomeGoProjects is the highest level logic for browsing to the
// awesome-go page, finding the specified section sect, and retrieving the
// associated projects from the page.
func listAwesomeGoProjects(ctx context.Context, sect string) (map[string]projectDesc, error) {
	// force max timeout of 15 seconds for retrieving and processing the data
	var cancel func()
	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	sel := fmt.Sprintf(`//p[text()[contains(., '%s')]]`, sect)

	// navigate
	if err := chromedp.Run(ctx, chromedp.Navigate(`https://github.com/avelino/awesome-go`)); err != nil {
		return nil, fmt.Errorf("could not navigate to github: %v", err)
	}

	// wait visible
	if err := chromedp.Run(ctx, chromedp.WaitVisible(sel)); err != nil {
		return nil, fmt.Errorf("could not get section: %v", err)
	}

	sib := sel + `/following-sibling::ul/li`

	// get project link text
	var projects []*cdp.Node
	if err := chromedp.Run(ctx, chromedp.Nodes(sib+`/child::a/text()`, &projects)); err != nil {
		return nil, fmt.Errorf("could not get projects: %v", err)
	}

	// get links and description text
	var linksAndDescriptions []*cdp.Node
	if err := chromedp.Run(ctx, chromedp.Nodes(sib+`/child::node()`, &linksAndDescriptions)); err != nil {
		return nil, fmt.Errorf("could not get links and descriptions: %v", err)
	}

	// check length
	if 2*len(projects) != len(linksAndDescriptions) {
		return nil, fmt.Errorf("projects and links and descriptions lengths do not match (2*%d != %d)", len(projects), len(linksAndDescriptions))
	}

	// process data
	res := make(map[string]projectDesc)
	for i := 0; i < len(projects); i++ {
		res[projects[i].NodeValue] = projectDesc{
			URL:         linksAndDescriptions[2*i].AttributeValue("href"),
			Description: strings.TrimPrefix(strings.TrimSpace(linksAndDescriptions[2*i+1].NodeValue), "- "),
		}
	}

	return res, nil
}
