package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/mail"
	"regexp"

	"sync"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var dbPool *sync.Pool

var tmpl = template.Must(template.ParseFiles(
	"templates/index.html",
	"templates/login.html",
	"templates/register.html",
	"templates/404.html"))

func main() {
	dbPool = &sync.Pool{
		New: func() interface{} {
			db, err := sql.Open("sqlite3", "file:sqlite.db?cache=shared")
			if err != nil {
				log.Fatal("Failed to create a new connection:", err)
			}
			return db
		},
	}
	r := http.NewServeMux()
	r.HandleFunc("/", index)
	r.HandleFunc("/login", login)
	r.HandleFunc("/register", register)
	r.HandleFunc("/discussions", discussions)
	r.HandleFunc("/discussion/{id}", discussion)
	r.HandleFunc("/new_discussion", newDiscussion)
	r.HandleFunc("/new_reply", newReply)
	r.HandleFunc("/settings", settings)
	http.ListenAndServe(":8080", r)
}

func setUserEmailCookie(w http.ResponseWriter, email string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "user_email",
		Value:    email,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // Set this to true for secure cookies in production
	})
}
func isValidUsername(username string) bool {
	validUsernameRegex := `^[a-z0-9._-]+$`
	match, _ := regexp.MatchString(validUsernameRegex, username)
	return match
}

func getUserEmailCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("user_email")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
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


