package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/mail"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
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
	r.HandleFunc("/discussions", discussions)
	r.HandleFunc("/discussion/{id}", discussion)
	r.HandleFunc("/new_discussion", newDiscussion)
	r.HandleFunc("/new_reply", newReply)
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

func newDiscussion(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl := template.Must(template.ParseFiles("templates/new_discussion.html"))
		tmpl.Execute(w, nil)
	} else if r.Method == "POST" {
		cookie, err := r.Cookie("user_email")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		userEmail := cookie.Value

		db := getDB()
		defer db.Close()

		title := r.FormValue("title")
		body := r.FormValue("body")

		_, err = db.Exec("INSERT INTO discussions (user_email, title, body) VALUES (?, ?, ?)", userEmail, title, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/discussions", http.StatusSeeOther)
	}
}

func newReply(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl := template.Must(template.ParseFiles("templates/new_reply.html"))
		tmpl.Execute(w, nil)
	} else if r.Method == "POST" {
		cookie, err := r.Cookie("user_email")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		userEmail := cookie.Value

		db := getDB()
		defer db.Close()

		discussionID := r.FormValue("discussion_id")
		parentID := r.FormValue("parent_id")
		body := r.FormValue("body")

		if parentID == "" {
			_, err = db.Exec("INSERT INTO replies (discussion_id, user_email, body) VALUES (?, ?, ?)", discussionID, userEmail, body)
		} else {
			_, err = db.Exec("INSERT INTO replies (discussion_id, parent_id, user_email, body) VALUES (?, ?, ?, ?)", discussionID, parentID, userEmail, body)
		}

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/discussion/"+discussionID, http.StatusSeeOther)
	}
}

func discussions(w http.ResponseWriter, r *http.Request) {
	db := getDB()
	defer db.Close()

	discussions, err := GetAllDiscussions(db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/discussions.html"))
	tmpl.Execute(w, discussions)
}

func discussion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.Error(w, "Missing discussion ID", http.StatusBadRequest)
		return
	}

	db := getDB()
	defer db.Close()

	discussion, err := GetDiscussionByID(db, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/discussion.html"))
	tmpl.Execute(w, discussion)
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
