package app

import (
	"context"
	"encoding/json"
	"github.com/adigunhammedolalekan/backendTest/models"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"os"
	"strings"
)

var JwtMiddleware = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		notAuth := []string{"/", "/api/account/new", "/api/account/authenticate",
		"/account/new", "/account/authenticate", "/forgotpassword", "/resetpassword",
		"/auth/google", "/auth/google/callback"} //List of endpoints that doesn't require auth
		requestPath := r.URL.Path //current request path

		if strings.HasPrefix(requestPath, "/static") ||
			strings.HasPrefix(requestPath, "/resetpassword"){
			next.ServeHTTP(w, r)
			return
		}

		//check if request does not need authentication, serve the request if it doesn't need it
		for _, value := range notAuth {

			if value == requestPath {
				next.ServeHTTP(w, r)
				return
			}
		}

		tokenValue := ""
		cookie, err := r.Cookie("AuthorizationKey") //Grab the token from cookie
		if cookie != nil {
			tokenValue = cookie.Value
		}

		if tokenValue == "" {
			tokenValue = r.Header.Get("AuthorizationKey") //or grab from header for API requests
		}

		if err != nil || tokenValue == "" { //Token is missing, returns with error code 403 Unauthorized
			response := &Response{
				Error: true, Message: "Unathorized request",
			}

			JSON(w, http.StatusForbidden, response)
			return
		}

		tk := &models.Token{}

		token, err := jwt.ParseWithClaims(cookie.Value, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil { //Malformed token, returns with http code 403 as usual
			response := &Response{
				Error: true, Message: "Invalid/Malformed auth token",
			}


			JSON(w, http.StatusForbidden, response)
			return
		}

		if !token.Valid { //Token is invalid, maybe not signed on this server
			response := &Response{
				Error: true, Message: "Invalid/Malformed auth token",
			}

			JSON(w, http.StatusForbidden, response)
			return
		}

		//Everything went well, proceed with the request and set the caller to the user retrieved from the parsed token
		ctx := context.WithValue(r.Context(), "account", tk)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r) //proceed in the middleware chain!
	})
}


type Response struct {

	Error bool `json:"error"`
	Message string `json:"message"`
	Data interface{} `json:"data"`
}

func JSON(w http.ResponseWriter, code int, r *Response) {

	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(r)
	if err != nil {
		w.WriteHeader(500)
		errResponse := &Response{
			Error: true, Message: "Something went wrong!",
		}
		bytes, _ := json.Marshal(errResponse)
		w.Write(bytes)
		return
	}

	w.WriteHeader(code)
	w.Write(data)
}
