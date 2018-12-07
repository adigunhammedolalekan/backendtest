package models

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"regexp"
	"strings"
)


var (
	userRegexp = regexp.MustCompile("^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+$")
	hostRegexp = regexp.MustCompile("^[^\\s]+\\.[^\\s]+$")
	ErrInvalidEmail = errors.New("Invalid email address")
)


type Account struct {

	gorm.Model
	Email string `json:"email"`
	Password string `json:"password"`
	GoogleId string `json:"google_id"`

	//Exclude columns from database
	Token string `sql:"-" gorm:"-"`
	Profile *Profile `sql:"-" gorm:"-"`
}

type GoogleAuthResponse struct {
	Id string `json:"id"`
	Name string `json:"name"`
}

type Profile struct {
	gorm.Model
	AccountId uint
	Fullname string
	Address string
	Telephone string
	Longitude float64
	Latitude float64
}

type Token struct {
	jwt.StandardClaims
	Account uint
}

type PasswordResetToken struct {
	gorm.Model
	AccountId uint `json:"account_id"`
	Hash string `json:"hash"`
}

func (a *Account) Validate() error {

	if err := a.validateEmail(); err != nil {
		return err
	}

	if len(a.Password) < 5 {
		return errors.New("Password is too soft. Please use a better password")
	}

	return nil
}


func (repo *Account) validateEmail() error {

	email := repo.Email

	if len(email) < 6 || len(email) > 254 {
		return ErrInvalidEmail
	}

	at := strings.LastIndex(email, "@")
	if at <= 0 || at > len(email)-3 {
		return ErrInvalidEmail
	}

	user := email[:at]
	host := email[at+1:]

	if len(user) > 64 {
		return ErrInvalidEmail
	}

	if !userRegexp.MatchString(user) || !hostRegexp.MatchString(host) {
		return ErrInvalidEmail
	}

	return nil
}




