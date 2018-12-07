package main

import (
	"github.com/adigunhammedolalekan/backendTest/app"
	"github.com/adigunhammedolalekan/backendTest/handlers"
	"github.com/adigunhammedolalekan/backendTest/repositories"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {

	godotenv.Load()
	db, err := app.CreateDbConnection(os.Getenv("DB_URL"))
	if err != nil {
		log.Fatal("Failed to connect to DB => ", err)
	}

	defer db.Close()

	templ := loadTemplates()
	router := mux.NewRouter()
	router.PathPrefix("/static/").
		Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./assets/static"))))

	accountRepo := repo.NewAccountRepository(db)
	accountHandler := handlers.NewAccountHandler(accountRepo, templ)
	accountApiHandler := handlers.NewAccountApiHandler(accountRepo)

	router.Use(app.JwtMiddleware)
	router.HandleFunc("/api/account/new", accountApiHandler.CreateNewAccount).Methods("POST")
	router.HandleFunc("/api/account/authenticate", accountApiHandler.AuthenticateAccount).Methods("POST")
	router.HandleFunc("/api/account/update", accountApiHandler.UpdateAccount).Methods("POST")
	router.HandleFunc("/account/new", accountHandler.RenderCreateAccountPage).Methods("GET")
	router.HandleFunc("/account/new", accountHandler.CreateNewAccount).Methods("POST")
	router.HandleFunc("/account/authenticate", accountHandler.RenderSignInPage).Methods("GET")
	router.HandleFunc("/account/authenticate", accountHandler.AuthenticateAccount).Methods("POST")
	router.HandleFunc("/profile", accountHandler.RenderProfile).Methods("GET")
	router.HandleFunc("/account/update", accountHandler.RenderUpdateAccount).Methods("GET")
	router.HandleFunc("/account/update", accountHandler.UpdateAccount).Methods("POST")
	router.HandleFunc("/signout", accountHandler.HandleLogOut).Methods("GET")
	router.HandleFunc("/forgotpassword", accountHandler.RenderForgotPasswordPage).Methods("GET")
	router.HandleFunc("/forgotpassword", accountHandler.HandleForgotPassword).Methods("POST")
	router.HandleFunc("/resetpassword/{hash}", accountHandler.RenderResetPasswordPage).Methods("GET")
	router.HandleFunc("/resetpassword", accountHandler.HandleResetPassword).Methods("POST")
	router.HandleFunc("/auth/google/callback", accountHandler.HandleGoogleAuthCallback)
	router.HandleFunc("/auth/google", accountHandler.HandleGoogleAuth).Methods("GET")

	address := ":" + os.Getenv("PORT")
	srv := &http.Server{
		Handler:      router,
		Addr:         address,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	if err := srv.ListenAndServe(); err == nil {
		log.Println("Server started at " + address)
	}
}

func loadTemplates() *template.Template {

	var allTemplates []string
	data, err := ioutil.ReadDir("./assets/templates")
	if err != nil {
		log.Fatal("Failed to read template data ", err)
	}

	for _, file := range data {

		filename := file.Name()
		if strings.HasSuffix(filename, ".html") {
			allTemplates = append(allTemplates, "./assets/templates/"+filename)
		}
	}

	templates, err := template.ParseFiles(allTemplates...)
	if err != nil {
		log.Fatal("Failed to parse template data ", err)
	}

	return templates
}
