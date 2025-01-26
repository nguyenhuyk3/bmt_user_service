package mail

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"user_service/global"
)

type EmailAddress struct {
	Address string `json:"address"`
	Name    string `json:"name"`
}

type Mail struct {
	From    EmailAddress
	To      []string
	Subject string
	Body    string
}

func buildMessage(mail Mail) string {
	msg := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\r\n"
	msg += fmt.Sprintf("From: %s\r\n", mail.From.Address)
	msg += fmt.Sprintf("To: %s\r\n", strings.Join(mail.To, ";"))
	msg += fmt.Sprintf("Subject: %s\r\n", mail.Subject)
	msg += fmt.Sprintf("\r\n%s\r\n", mail.Body)

	return msg
}

func getMailTemplate(nameTemplate string, dataTemplate map[string]interface{}) (string, error) {
	htmlTemplate := new(bytes.Buffer)
	t := template.Must(template.New(nameTemplate).ParseFiles("templates/" + nameTemplate))

	err := t.Execute(htmlTemplate, dataTemplate)
	if err != nil {
		return "", err
	}

	return htmlTemplate.String(), nil
}

func send(to []string, from string,
	purpose string,
	htmlTemplate string) error {
	var subject string
	switch purpose {
	case global.REGISTRATION_OTP_KEY:
		subject = "Xác thực mã OTP"
	case global.FORGOT_PASSWORD_PURPOSE:
		subject = "Quên mật khẩu"
	default:
		return errors.New("invalid purpose")
	}

	contentEmail := Mail{
		From:    EmailAddress{Address: from, Name: "Nguyễn Quốc Huy"},
		To:      to,
		Subject: subject,
		Body:    htmlTemplate,
	}
	messageMail := buildMessage(contentEmail)
	mailSetting := global.Config.ServiceSetting.MailSetting
	auth := smtp.PlainAuth("", mailSetting.Username, mailSetting.Password, mailSetting.Host)
	// Send smtp
	err := smtp.SendMail(mailSetting.Host+":587", auth, from, to, []byte(messageMail))
	if err != nil {
		return err
	}

	return nil
}

func SendTemplateEmailOtp(
	to []string, from string,
	nameTemplate string,
	purpose string,
	dataTemplate map[string]interface{},
) error {
	htmlBody, err := getMailTemplate(nameTemplate, dataTemplate)
	if err != nil {
		return err
	}

	return send(to, from, purpose, htmlBody)
}
