package app

import (
	"github.com/adigunhammedolalekan/backendTest/models"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"net/http"
)

//CreateDbConnection connects to MySQL database and returns connection pointer
func CreateDbConnection(url string) (*gorm.DB, error) {

	db, err := gorm.Open("postgres", url)
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(&models.Account{}, &models.Profile{}, &models.PasswordResetToken{})
	return db, nil
}

//Parse authentication data from request context, returns nil pointer
//if user is not authenticated
func ParseToken(r *http.Request) *models.Token {

	token, ok := r.Context().Value("account") . (*models.Token)
	if !ok {
		return nil
	}

	if token.Account <= 0 {
		return nil
	}

	return token
}
