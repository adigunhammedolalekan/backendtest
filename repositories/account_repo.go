package repo

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/adigunhammedolalekan/backendTest/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
	"os"
)

type AccountRepository struct {
	db *gorm.DB
}

func NewAccountRepository(db *gorm.DB) *AccountRepository {

	return &AccountRepository{
		db:db,
	}
}

func (repo *AccountRepository) CreateAccount(account *models.Account) (*models.Account, error) {

	if err := account.Validate(); err != nil {
		return nil, err
	}

	existingAccount := repo.GetAccount(account.Email)
	if existingAccount != nil {
		return nil, fmt.Errorf("account with email %s already exists", account.Email)
	}

	account.Password = repo.hashPassword(account.Password)
	tx := repo.db.Begin()

	if err := tx.Create(account).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	profile := &models.Profile{
		AccountId: account.ID,
	}
	if err := tx.Create(profile).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	tx.Commit()
	account.Token = repo.generateJWT(account.ID)
	return account, nil
}

func (repo *AccountRepository) ValidateLoginCredentials(email, password string) error {

	account := &models.Account{
		Email:email, Password:password,
	}

	if err := account.Validate(); err != nil {
		return err
	}

	account = repo.GetAccount(email)
	if account == nil {
		return errors.New("failed to validate login credentials. Account not found")
	}

	if ok := repo.comparePassword(account.Password, password); !ok {
		return errors.New("failed to validate login credentials. Invalid password")
	}

	return nil
}

func (repo *AccountRepository) UpdateAccount(account uint, profile *models.Profile) error {
	return repo.db.Table("profiles").Update(profile).Error
}

func (repo *AccountRepository) GetAccount(email string) *models.Account {

	account := &models.Account{}
	err := repo.db.Table("accounts").Where("email = ?", email).First(account).Error
	if err != nil {
		return nil
	}

	account.Profile = repo.GetProfile(account.ID)
	return account
}

func (repo *AccountRepository) GetAccountWithToken(email string) *models.Account {

	account := repo.GetAccount(email)
	if account == nil {
		return nil
	}

	account.Token = repo.generateJWT(account.ID)
	account.Profile = repo.GetProfile(account.ID)
	return account
}

func (repo *AccountRepository) GetAccountById(id uint) *models.Account {

	account := &models.Account{}
	err := repo.db.Table("accounts").Where("id = ?", id).First(account).Error
	if err != nil {
		fmt.Println(err)
		return nil
	}

	account.Profile = repo.GetProfile(account.ID)
	return account
}

func (repo *AccountRepository) GetProfile(account uint) *models.Profile {

	profile := &models.Profile{}
	err := repo.db.Table("profiles").Where("account_id = ?", account).First(profile).Error
	if err != nil {
		return nil
	}

	if profile.Fullname == "" {
		profile.Fullname = "Awesome Human!"
	}
	return profile
}

func (repo *AccountRepository) SendForgotPasswordEmail(account *models.Account) (error) {

	uniqueHash := createUniqueHash(os.Getenv("JWT_SECRET") + account.Email)
	body := "Click the link below to reset your password http://localhost:9001/resetpassword/" + uniqueHash

	token := &models.PasswordResetToken{
		AccountId: account.ID, Hash: uniqueHash,
	}

	if err := repo.db.Create(token).Error; err != nil {
		return err
	}

	mailRequest := &MailRequest{
		Subject: "Password Reset Instruction",
		To: account.Email,
		Body: body,
	}

	return SendEmail(mailRequest)
}

func (repo *AccountRepository) ResetPassword(hash, newPassword string) (error) {

	token := &models.PasswordResetToken{}
	err := repo.db.Table("password_reset_tokens").Where("hash = ?", hash).First(token).Error
	if err != nil {
		return err
	}

	err = repo.db.Table("accounts").Where("id = ?", token.AccountId).UpdateColumn("password",
		repo.hashPassword(newPassword)).Error
	if err != nil {
		return err
	}

	return nil
}

func (repo *AccountRepository) AuthenticateGoogleAccount(user *models.GoogleAuthResponse) (*models.Account, error) {

	account := &models.Account{}
	notFound := repo.db.Table("accounts").Where("google_id = ?", user.Id).First(account).RecordNotFound()
	if notFound {

		account.GoogleId = user.Id
		tx := repo.db.Begin()
		if err := tx.Create(account).Error; err != nil {
			tx.Rollback()
			return nil, err
		}

		profile := &models.Profile{
			AccountId: account.ID, Fullname: user.Name,
		}

		if err := tx.Create(profile).Error; err != nil {
			tx.Rollback()
			return nil, err
		}

		tx.Commit()
		return repo.GetAccountByAttr("google_id", user.Id), nil
	}

	return repo.GetAccountByAttr("google_id", user.Id), nil
}

func (repo *AccountRepository) GetAccountByAttr(col string, value interface{}) (*models.Account) {

	account := &models.Account{}
	err := repo.db.Table("accounts").Where(col + " = ?", value).First(account).Error
	if err != nil {
		return nil
	}

	account.Profile = repo.GetProfile(account.ID)
	account.Token = repo.generateJWT(account.ID)
	return account
}

func createUniqueHash(key string) string {

	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString([]byte(hasher.Sum(nil)))
}

func (repo *AccountRepository) generateJWT(id uint) string {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &models.Token{
		Account: id,
	})

	tokenString, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	return tokenString
}

func (repo *AccountRepository) hashPassword(password string) string {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return ""
	}

	return string(hashedPassword)
}

func (repo *AccountRepository) comparePassword(hashed, plain string) bool {

	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	if err != nil {
		return false
	}

	return true
}

