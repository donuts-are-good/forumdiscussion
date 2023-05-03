package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/mail"

	"golang.org/x/crypto/bcrypt"
)

var users = make(map[string]*User)
var tmpl = template.Must(template.ParseFiles(
	"templates/index.html",
	"templates/login.html",
	"templates/register.html",
	"templates/404.html"))

func main() {
	r := http.NewServeMux()
	r.HandleFunc("/", index)
	r.HandleFunc("/login", login)
	r.HandleFunc("/register", register)
	http.ListenAndServe(":8080", r)
}

func index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		notFoundHandler(w, r)
		return
	}
	tmpl.ExecuteTemplate(w, "index.html", nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		token := setCSRFToken(w, r)
		tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"csrfField": template.HTML(`<input type="hidden" name="csrf_token" value="` + token + `">`),
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := verifyCSRFToken(r); err != nil {
		http.Error(w, "Invalid CSRF token", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	user, ok := users[email]

	if !ok {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if !checkPassword(password, user.Password) {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Welcome, %s!", email)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		token := setCSRFToken(w, r)
		tmpl.ExecuteTemplate(w, "register.html", map[string]interface{}{
			"csrfField": template.HTML(`<input type="hidden" name="csrf_token" value="` + token + `">`),
		})
		return
	}

	if r.Method != http.MethodPost {
		tmpl.ExecuteTemplate(w, "register.html", nil)
		return
	}

	if err := verifyCSRFToken(r); err != nil {
		http.Error(w, "Invalid CSRF token", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if !isValidEmail(email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	if _, exists := users[email]; exists {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	user := &User{Email: email, Password: hashedPassword}
	users[email] = user

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPassword(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func setCSRFToken(w http.ResponseWriter, r *http.Request) string {
	token := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
	})
	return token
}

func getCSRFToken(r *http.Request) string {
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func verifyCSRFToken(r *http.Request) error {
	csrfToken := r.FormValue("csrf_token")
	cookieToken := getCSRFToken(r)

	if csrfToken == "" || cookieToken == "" || csrfToken != cookieToken {
		return errors.New("invalid CSRF token")
	}
	return nil
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	tmpl.ExecuteTemplate(w, "404.html", nil)
}
