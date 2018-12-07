package handlers

import (
	"html/template"
	"net/http"
)

type IndexHandler struct {
	template *template.Template
}

func NewIndexHandler(template *template.Template) *IndexHandler {

	return &IndexHandler{
		template: template,
	}
}

func (i *IndexHandler) IndexPage(w http.ResponseWriter, r *http.Request)  {
	i.template.Lookup("index.html").Execute(w, nil)
}
