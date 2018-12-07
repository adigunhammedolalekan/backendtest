package repo

import (
	"fmt"
	"github.com/mailjet/mailjet-apiv3-go"
	"os"
)

type MailRequest struct {

	Subject string `json:"subject"`
	Body string `json:"body"`
	To string `json:"to"`
	Name string `json:"name"`

}

func SendEmail(request *MailRequest) error {

	mailjetClient := mailjet.NewMailjetClient(os.Getenv("MJ_APIKEY_PUBLIC"), os.Getenv("MJ_APIKEY_PRIVATE"))
	email := &mailjet.InfoSendMail {
		FromEmail: os.Getenv("email"),
		FromName: "Backend Test",
		Subject: "Password Reset Instruction",
		HTMLPart: request.Body,
		Recipients: []mailjet.Recipient {
			mailjet.Recipient {
				Email: request.To,
			},
		},
	}

	res, err := mailjetClient.SendMail(email)
	if err != nil {
		fmt.Println(err)
		return err
	}

	fmt.Println("Sent! ", res)
	return nil
}
