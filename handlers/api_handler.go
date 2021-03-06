package handlers

import (
	"encoding/json"
	"github.com/adigunhammedolalekan/backendTest/app"
	"github.com/adigunhammedolalekan/backendTest/models"
	"github.com/adigunhammedolalekan/backendTest/repositories"
	"github.com/gorilla/mux"
	"net/http"
	"strconv"
)

//AccountApiHandler encapsulates handlers that handles Json API requests
//
type AccountApiHandler struct {
	repo *repo.AccountRepository
}

//NewAccountApiHandler returns an instance of AccountApiHandler
func NewAccountApiHandler(repo *repo.AccountRepository) *AccountApiHandler {

	return &AccountApiHandler{
		repo:repo,
	}
}

//CreateNewAccount handles create account API request
func (handler *AccountApiHandler) CreateNewAccount(w http.ResponseWriter, r *http.Request)  {

	//Decode request's body into Go struct or return error
	//if the json body is malformed
	account := models.Account{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&account); err != nil {
		JSON(w, 200, &Response{
			Error:true, Message: "Invalid request. Malformed json body",
		})
		return
	}

	//create the account
	newAccount, err := handler.repo.CreateAccount(&account)
	if err != nil {
		JSON(w, 200, &Response{
			Error:true, Message: err.Error(),
		})

		return
	}

	//Send JSON response
	JSON(w, 200, &Response{
		Error:false, Message: "account.created", Data:newAccount,
	})
}

//AuthenticateAccount handles user authentication API request
func (handler *AccountApiHandler) AuthenticateAccount(w http.ResponseWriter, r *http.Request)  {

	account := models.Account{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&account); err != nil {
		JSON(w, 200, &Response{
			Error:true, Message: "Invalid request. Malformed json body",
		})
		return
	}

	if err := handler.repo.ValidateLoginCredentials(account.Email, account.Password); err != nil {
		JSON(w, 200, &Response{
			Error:true, Message: err.Error(),
		})
		return
	}

	//Account is validated. Get account from database
	// and generate a JWT token for the
	//authenticated user
	authenticatedAccount := handler.repo.GetAccountWithToken(account.Email)
	JSON(w, 200, &Response{
		Error: false, Message: "authentication successful", Data: authenticatedAccount,
	})
}

//UpdateAccount handles user details update API request
func (handler *AccountApiHandler) UpdateAccount(w http.ResponseWriter, r *http.Request)  {

	profile := models.Profile{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&profile); err != nil {
		JSON(w, 200, &Response{
			Error:true, Message: "Invalid request. Malformed json body",
		})
		return
	}

	//Makes sure the user is authenticated
	//or returns 403 authorized error if
	//the caller/user in not authenticated
	token := app.ParseToken(r)
	if token == nil {
		JSON(w, 403, &Response{
			Error:true, Message: "Unauthorized request",
		})
		return
	}

	err := handler.repo.UpdateAccount(token.Account, &profile)
	if err != nil {
		JSON(w, 200, &Response{
			Error:true, Message: "Something went wrong while updating profile. Please retry",
		})
		return
	}

	account := handler.repo.GetAccountById(token.Account)
	JSON(w, 200, &Response{
		Error:false, Message: "profile updated", Data: account,
	})
}

//FetchCurrentUserProfile returns JSON rep for the caller profile
//providing the user has a valid JWT token
func (handler *AccountApiHandler) FetchCurrentUserProfile(w http.ResponseWriter, r *http.Request) {

	//Makes sure the user is authenticated
	//or returns 403 authorized error if
	//the caller/user in not authenticated
	token := app.ParseToken(r)
	if token == nil {
		JSON(w, 403, &Response{
			Error:true, Message: "Unauthorized request",
		})
		return
	}

	account := handler.repo.GetAccountById(token.Account)
	JSON(w, 200,&Response{
		Error: false, Message: "profile.fetched", Data: account,
	})
}

func (handler *AccountApiHandler) FetchProfile(w http.ResponseWriter, r *http.Request) {

	//Makes sure the user is authenticated
	//or returns 403 authorized error if
	//the caller/user in not authenticated
	token := app.ParseToken(r)
	if token == nil {
		JSON(w, 403, &Response{
			Error:true, Message: "Unauthorized request",
		})
		return
	}

	//Grab user id from request path.
	//returns error if converting to integer
	//is not successful
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		JSON(w, 200, &Response{
			Error: true, Message: "invalid account ID", Data: nil,
		})
		return
	}

	account := handler.repo.GetAccountById(uint(id))
	if account == nil {
		//account not found
		//respond with a 404
		JSON(w, 404, &Response{
			Error:true, Message: "Account not found", Data: nil,
		})
		return
	}

	JSON(w, 200, &Response{
		Error: false, Message: "profile.fetched", Data: account,
	})
}