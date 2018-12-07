package handlers

import (
	"encoding/json"
	"net/http"
)

//Response stores response information.
type Response struct {

	//True if error occurred while processing the request
	Error bool `json:"error"`

	//Message response status message
	Message string `json:"message"`

	//Additional data
	Data interface{} `json:"data"`
}

//JSON - output/respond to request with Json data
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
