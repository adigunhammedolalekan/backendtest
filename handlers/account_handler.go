package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/adigunhammedolalekan/backendTest/app"
	"github.com/adigunhammedolalekan/backendTest/models"
	"github.com/adigunhammedolalekan/backendTest/repositories"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

//Google oauth get user profile API uri
const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

//AccountHandler handles all request to create and manipulate account
type AccountHandler struct {

	//AccountRepository is the account database
	repo *repo.AccountRepository

	//template cache.
	template *template.Template
}

//NewAccountHandler returns a new AccountHandler pointer.
func NewAccountHandler(repo *repo.AccountRepository, template *template.Template) *AccountHandler {

	return &AccountHandler{
		repo:repo, template:template,
	}
}

//CreateNewAccount handles CreateAccount request
func (handler *AccountHandler) CreateNewAccount(w http.ResponseWriter, r *http.Request)  {

	//Check if user is currently authenticated.
	//User must first signout before attempting to
	//create a new account. Redirect to profile if
	//we currently have the user authenticated
	token := app.ParseToken(r)
	if token != nil {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}

	//process form data
	err := r.ParseForm()
	if err != nil {
		handler.template.Lookup("create_account.html").Execute(w, &Response{
			Error:true, Message: "Failed to process form data",
		})
		return
	}

	//Grab form data and create the account
	//return error incase there is any e.g
	//creating an account with the same email
	account := &models.Account{}
	account.Email = r.Form.Get("email")
	account.Password = r.Form.Get("password")

	newAccount, err := handler.repo.CreateAccount(account);
	if err != nil {
		handler.template.Lookup("create_account.html").Execute(w, &Response{
			Error:true, Message: err.Error(), Data: account,
		})
		return
	}

	//Create and set cookie
	cookie := &http.Cookie{
		Value: newAccount.Token,
		Expires: time.Now().Add(60000 * time.Minute),
		Name: "AuthorizationKey",
		Secure: false,
		Path: "/",
	}

	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/profile", http.StatusFound)
}

//AuthenticateAccount handles account authentication request
func (handler *AccountHandler) AuthenticateAccount(w http.ResponseWriter, r *http.Request)  {

	////Check if user is currently authenticated.
	//	//User must first signout before attempting to
	//	//create a new account. Redirect to profile if
	//	//we currently have the user authenticated
	////
	token := app.ParseToken(r)
	if token != nil {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}

	//process form data
	err := r.ParseForm()
	if err != nil {
		handler.template.Lookup("sign_in.html").Execute(w, &Response{
			Error:true, Message: "Failed to process form data",
		})
		return
	}

	account := &models.Account{}
	account.Email = r.Form.Get("email")
	account.Password = r.Form.Get("password")

	err = handler.repo.ValidateLoginCredentials(account.Email, account.Password);
	if err != nil {
		handler.template.Lookup("sign_in.html").Execute(w, &Response{
			Error:true, Message: err.Error(), Data: account,
		})
		return
	}

	//authentication successful. create and set cookie
	authAccount := handler.repo.GetAccountWithToken(account.Email)
	cookie := &http.Cookie{
		Value: authAccount.Token,
		Expires: time.Now().Add(60000 * time.Minute),
		Name: "AuthorizationKey",
		Secure: false,
		Path: "/",
	}

	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/profile", http.StatusFound) //redirect to profile
}


func (handler *AccountHandler) UpdateAccount(w http.ResponseWriter, r *http.Request)  {

	token := app.ParseToken(r)
	if token == nil {
		http.Redirect(w, r, "/account/authenticate", http.StatusFound)
		return
	}

	account := handler.repo.GetAccountById(token.Account)
	err := r.ParseForm()
	if err != nil {
		handler.template.Lookup("edit_profile.html").Execute(w, &Response{
			Error: true, Message: "invalid form data", Data: account,
		})
		return
	}

	form := r.Form
	profile := &models.Profile{}
	profile.Fullname = form.Get("fullname")
	profile.Address = form.Get("address")
	profile.Telephone = form.Get("telephone")

	err = handler.repo.UpdateAccount(token.Account, profile)
	if err != nil {
		handler.template.Lookup("edit_profile.html").Execute(w, &Response{
			Error: true, Message: err.Error(), Data: account,
		})
		return
	}

	//Redirect back to profile
	http.Redirect(w, r, "/profile", http.StatusFound)
}

func (handler *AccountHandler) HandleLogOut(w http.ResponseWriter, r *http.Request)  {

	cookie := &http.Cookie{
		Value: "",
		Name: "AuthorizationKey",
		Expires: time.Unix(0, 0),
		Secure: false,
		Path: "/",
	}

	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/account/authenticate", http.StatusFound)
}

func (handler *AccountHandler) RenderProfile(w http.ResponseWriter, r *http.Request)  {

	token := app.ParseToken(r)
	if token == nil {
		http.Redirect(w, r, "/account/authenticate", http.StatusFound)
		return
	}

	profile := handler.repo.GetAccountById(token.Account)
	handler.template.Lookup("profile.html").Execute(w,
		&Response{
			Error: false, Message: "profile.fetched", Data: profile,
		})
}

func (handler *AccountHandler) HandleForgotPassword(w http.ResponseWriter, r *http.Request)  {

	if err := r.ParseForm(); err != nil {
		handler.template.Lookup("forgot_password.html").Execute(w,
			&Response{
				Error: true, Message: "invalid form data",
			})
		return
	}

	email := r.Form.Get("email")
	account := handler.repo.GetAccount(email)
	if account == nil {
		handler.template.Lookup("forgot_password.html").Execute(w,
			&Response{
				Error: true, Message: "account with email " + email + " not found",
			})
		return
	}

	err := handler.repo.SendForgotPasswordEmail(account)
	if err != nil {
		handler.template.Lookup("forgot_password.html").Execute(w,
			&Response{
				Error: true, Message: err.Error(),
			})
		return
	}

	handler.template.Lookup("forgot_password.html").Execute(w,
		&Response{
			Error: false, Message: "An email with instruction on how to reset password has been sent to " + email,
		})
}

func (handler *AccountHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request)  {

	if err := r.ParseForm(); err != nil {
		handler.template.Lookup("reset_password.html").Execute(w,
			&Response{
				Error: true, Message: "invalid form data",
			})
		return
	}

	newPassword := r.Form.Get("new_password")
	newPasswordConfirm := r.Form.Get("new_password_confirm")
	hash := r.Form.Get("hash")
	if newPassword != newPasswordConfirm {
		handler.template.Lookup("forgot_password.html").Execute(w,
			&Response{
				Error: true, Message: "password does not match!",
			})
		return
	}

	err := handler.repo.ResetPassword(hash, newPassword)
	if err != nil {
		handler.template.Lookup("forgot_password.html").Execute(w,
			&Response{
				Error: true, Message: err.Error(),
			})
		return
	}
	http.Redirect(w, r, "/account/authenticate", http.StatusFound)
}

func (handler *AccountHandler) HandleGoogleAuth(w http.ResponseWriter, r *http.Request)  {


	var oauthConfig = &oauth2.Config{
		RedirectURL: "http://localhost:9001/auth/google/callback",
		ClientID: os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}

	oauthState := handler.generateGoogleAuthStateCookie(w)
	authUrl := oauthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, authUrl, http.StatusTemporaryRedirect)
}

func (handler *AccountHandler) HandleGoogleAuthCallback(w http.ResponseWriter, r *http.Request)  {

	oauthState, err := r.Cookie("oauthState")

	if err != nil {
		http.Redirect(w, r, "/account/authenticate", http.StatusTemporaryRedirect)
		return
	}

	if r.FormValue("state") != oauthState.Value {
		http.Redirect(w, r, "/account/authenticate", http.StatusTemporaryRedirect)
		return
	}

	data, err := handler.fetchUserProfile(r.FormValue("code"))
	if err != nil {
		http.Redirect(w, r, "/account/authenticate", http.StatusTemporaryRedirect)
		return
	}

	googleUser := &models.GoogleAuthResponse{}
	err = json.Unmarshal(data, googleUser)
	if err != nil {
		http.Redirect(w, r, "/account/authenticate", http.StatusTemporaryRedirect)
		return
	}

	account, err := handler.repo.AuthenticateGoogleAccount(googleUser)
	if err != nil {
		http.Redirect(w, r, "/account/authenticate", http.StatusFound)
		return
	}

	cookie := &http.Cookie{
		Value: account.Token,
		Expires: time.Now().Add(60000 * time.Minute),
		Name: "AuthorizationKey",
		Secure: false,
		Path: "/",
	}

	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/profile", http.StatusFound)
}

func (handler *AccountHandler) fetchUserProfile(code string) ([]byte, error) {


	var oauthConfig = &oauth2.Config{
		RedirectURL: "http://localhost:9001/auth/google/callback",
		ClientID: os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}

	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}

	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return contents, nil
}

func (handler *AccountHandler) generateGoogleAuthStateCookie(w http.ResponseWriter) string {

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthState",
	Value: state,
	Path: "/",
	Expires: time.Now().Add(365 * 24 * time.Hour)}
	http.SetCookie(w, &cookie)

	return state
}

func (handler *AccountHandler) RenderCreateAccountPage(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("AuthorizationKey")
	if err == nil && cookie.Value != "" {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}

	createAccountPage := handler.template.Lookup("create_account.html")
	createAccountPage.Execute(w, nil)
}

func (handler *AccountHandler) RenderSignInPage(w http.ResponseWriter, r *http.Request)  {

	cookie, err := r.Cookie("AuthorizationKey")
	if err == nil && cookie.Value != "" {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}

	signInPage := handler.template.Lookup("sign_in.html")
	signInPage.Execute(w, nil)
}

func (handler *AccountHandler) RenderUpdateAccount(w http.ResponseWriter, r *http.Request)  {

	token := app.ParseToken(r)
	if token == nil {
		handler.template.Lookup("sign_in.html").Execute(w,
			&Response{
				Error: true, Message: "You need to sign in first", Data: nil,
			})
		return
	}

	account := handler.repo.GetAccountById(token.Account)
	updateAccountPage := handler.template.Lookup("edit_profile.html")
	updateAccountPage.Execute(w, &Response{
		Error: false, Message: "", Data: account,
	})
}

func (handler *AccountHandler) RenderForgotPasswordPage(w http.ResponseWriter, r *http.Request)  {

	cookie, err := r.Cookie("AuthorizationKey")
	if err == nil && cookie.Value != "" {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}

	forgotPasswordPage := handler.template.Lookup("forgot_password.html")
	forgotPasswordPage.Execute(w, nil)
}

func (handler *AccountHandler) RenderResetPasswordPage(w http.ResponseWriter, r *http.Request)  {

	cookie, err := r.Cookie("AuthorizationKey")
	if err == nil && cookie.Value != "" {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}

	data := mux.Vars(r)
	resetPasswordPage := handler.template.Lookup("reset_password.html")
	resetPasswordPage.Execute(w, &Response{
		Error: false, Message: "", Data: data["hash"],
	})
}
