package main

import (
	"database/sql"
	"html/template"
	"log"
	"math/rand"
	"net/http"

	"github.com/gorilla/mux"
)

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

	if err := verifyCSRFToken(r); err != nil {
		http.Error(w, "Invalid CSRF token", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	db := dbPool.Get().(*sql.DB)
	defer dbPool.Put(db)

	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE email = ?", email).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		} else {
			http.Error(w, "Error retrieving user", http.StatusInternalServerError)
		}
		return
	}

	if !checkPassword(password, hashedPassword) {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Set user's email in a secure cookie
	setUserEmailCookie(w, email)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		token := setCSRFToken(w, r)
		tmpl.ExecuteTemplate(w, "register.html", map[string]interface{}{
			"csrfField": template.HTML(`<input type="hidden" name="csrf_token" value="` + token + `">`),
		})
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

	db := dbPool.Get().(*sql.DB)
	defer dbPool.Put(db)

	var existingEmail string
	err := db.QueryRow("SELECT email FROM users WHERE email = ?", email).Scan(&existingEmail)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "Error checking for existing user", http.StatusInternalServerError)
		return
	}

	if existingEmail != "" {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (email, password) VALUES (?, ?)", email, hashedPassword)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func newDiscussion(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl := template.Must(template.ParseFiles("templates/new_discussion.html"))
		tmpl.Execute(w, nil)
	} else if r.Method == "POST" {
		userEmail, err := getUserEmailCookie(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		db := dbPool.Get().(*sql.DB)
		defer dbPool.Put(db)

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
		userEmail, err := getUserEmailCookie(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		db := dbPool.Get().(*sql.DB)
		defer dbPool.Put(db)

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
	db := dbPool.Get().(*sql.DB)
	defer dbPool.Put(db)

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

	db := dbPool.Get().(*sql.DB)
	defer dbPool.Put(db)

	discussion, err := GetDiscussionByID(db, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/discussion.html"))
	tmpl.Execute(w, discussion)
}
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	tmpl.ExecuteTemplate(w, "404.html", nil)
}

func settings(w http.ResponseWriter, r *http.Request) {
	userEmail, err := getUserEmailCookie(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	db := dbPool.Get().(*sql.DB)
	defer dbPool.Put(db)

	var currentUser User
	err = db.QueryRow("SELECT id, email, username, discriminator FROM users WHERE email = ?", userEmail).Scan(
		&currentUser.ID,
		&currentUser.Email,
		&currentUser.Profile.Username,
		&currentUser.Profile.Discriminator,
	)
	if err != nil {
		log.Println("error adding user settings: ", err)
	}

	if r.Method == "GET" {
		tmpl := template.Must(template.ParseFiles("templates/settings.html"))
		tmpl.Execute(w, currentUser)
	} else if r.Method == "POST" {
		username := r.FormValue("username")

		isValidUsername := isValidUsername(username)
		if !isValidUsername {
			http.Error(w, "Invalid username format", http.StatusBadRequest)
			return
		}

		if currentUser.Profile.Discriminator == 0 {
			currentUser.Profile.Discriminator = rand.Intn(9999) // Generate a random number between 0 and 9999
		}

		_, err := db.Exec("UPDATE users SET username = ?, discriminator = ? WHERE email = ?", username, currentUser.Profile.Discriminator, userEmail)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/settings", http.StatusSeeOther)
	}
}