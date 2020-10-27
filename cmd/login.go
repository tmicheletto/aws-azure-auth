package cmd

import (
	"aws-azure-auth/internal/pkg/chrome"
	"aws-azure-auth/internal/pkg/saml"
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chromedp/cdproto/cdp"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os/exec"
	"strings"
)

const AZURE_AD_SSO = "autologon.microsoftazuread-sso.com"
const AWS_CREDENTIALS_FILE_NAME = "credentials"

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
	azureADUserName := viper.GetString("azureADUserName")

	driver, dispose := chrome.NewDriver()
	defer dispose()

	if err := driver.Navigate(); err != nil {
		return err
	}

	prompt := promptui.Prompt{Label: "Please enter your AD username", Default: azureADUserName}
	username, err := prompt.Run()
	if err != nil {
		return err
	}

	if err = driver.SendUsername(username); err != nil {
		return err
	}

	prompt = promptui.Prompt{Label: "Please enter your password", Mask: '*'}
	password, err := prompt.Run()
	if err != nil {
		return err
	}

	if err = driver.SendPassword(password); err != nil {
		return nil
	}

	prompt = promptui.Prompt{Label: "Please enter the code sent to your device"}
	code, err := prompt.Run()
	if err != nil {
		return err
	}

	accounts, err := driver.SendCode(code)
	if err != nil {
		return err
	}

	roles, err := saml.ParseRolesFromSAMLResponse(driver.SAMLResponse)
	if err != nil {
		return err
	}

	accountsMap := buildAccountsMap(accounts)
	options := buildAccountPrompt(roles, accountsMap)

	listPrompt := promptui.Select{
		Label: "Please select the role you want to assume",
		Items: options,
	}

	roleIdx, _, err := listPrompt.Run()
	if err != nil {
		return err
	}

	config, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return err
	}

	// assume role
	svc := sts.New(config)
	input := parseRole(roles[roleIdx], driver.SAMLResponse)
	out, err := svc.AssumeRoleWithSAMLRequest(input).Send(context.TODO())
	if err != nil {
		return err
	}
	fmt.Printf("Successfully assumed role %s. Writing credentials...\n", *input.RoleArn)
	return writeCredentials(out.Credentials)
}

func writeCredentials(creds *sts.Credentials) error {
	cmd := exec.Command("aws", "configure", "set", "aws_access_key_id", *creds.AccessKeyId)
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("aws", "configure", "set", "aws_secret_access_key", *creds.SecretAccessKey)
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("aws", "configure", "set", "aws_session_token", *creds.SessionToken)
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func parseRole(role string, samlAssertion string) *sts.AssumeRoleWithSAMLInput {
	tokens := strings.Split(role, ",")

	return &sts.AssumeRoleWithSAMLInput{
		RoleArn:         aws.String(tokens[0]),
		PrincipalArn:    aws.String(tokens[1]),
		SAMLAssertion:   aws.String(samlAssertion),
		DurationSeconds: aws.Int64(2400),
	}
}

func parseAccountNumberFromRoleARN(roleArn string) string {
	tokens := strings.Split(roleArn, ":")
	return tokens[4]
}

func buildAccountsMap(accounts []*cdp.Node) map[string]string {
	accountsMap := make(map[string]string)
	for _, account := range accounts {
		node := (*account).Children[0]
		accountText := (*node).NodeValue
		tokens := strings.Split(accountText, "(")
		tokens = strings.Split(tokens[1], ")")

		accountsMap[tokens[0]] = accountText
	}
	return accountsMap
}

func buildAccountPrompt(roles []string, accountsMap map[string]string) []string {
	roleArns := make([]string, 0)
	for _, role := range roles {
		tokens := strings.Split(role, ",")
		roleArn := tokens[0]

		accountNumber := parseAccountNumberFromRoleARN(roleArn)
		roleArns = append(roleArns, fmt.Sprintf("%s -> Role: %s", accountsMap[accountNumber], roleArn))
	}
	return roleArns
}
