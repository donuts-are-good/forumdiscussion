package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/mux"
)

func index(w http.ResponseWriter, r *http.Request) {
	db := dbPool.Get().(*sql.DB)
	defer dbPool.Put(db)

	isSetupCompleted, err := IsSetupCompleted(db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !isSetupCompleted {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}

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

	var hashedPassword, username string
	err := db.QueryRow("SELECT password, username FROM users WHERE email = ?", email).Scan(&hashedPassword, &username)
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

	setUserEmailCookie(w, email)

	if username == "" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
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

	_, err = db.Exec("INSERT INTO users (email, password, username) VALUES (?, ?, ?)", email, hashedPassword, "")
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

		var userID int
		err = db.QueryRow("SELECT id FROM users WHERE email = ?", userEmail).Scan(&userID)
		if err != nil {
			http.Error(w, "Error retrieving user ID", http.StatusInternalServerError)
			return
		}

		title := r.FormValue("title")
		body := r.FormValue("body")

		_, err = db.Exec("INSERT INTO discussions (user_id, title, body) VALUES (?, ?, ?)", userID, title, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/discussions", http.StatusSeeOther)
	}
}

func newReply(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	discussionID := vars["discussionID"]
	parentID := r.URL.Query().Get("parent_id")

	if r.Method == "GET" {
		tmpl := template.Must(template.ParseFiles("templates/new_reply.html"))

		data := map[string]interface{}{
			"ID": discussionID,
		}

		if parentID != "" {
			db := dbPool.Get().(*sql.DB)
			defer dbPool.Put(db)

			parentReply, err := GetReplyByID(db, parentID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			data["ParentReply"] = parentReply

		}

		tmpl.Execute(w, data)
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

	userEmail, err := getUserEmailCookie(r)
	isLoggedIn := err == nil

	var username string
	var avatar string
	if isLoggedIn {
		user, err := GetUserByEmail(db, userEmail)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		username = user.Profile.Username
		avatar = user.Profile.Avatar
	}
	data := struct {
		Discussions []Discussion
		IsLoggedIn  bool
		Username    string
		Avatar      string
	}{
		discussions,
		isLoggedIn,
		username,
		avatar,
	}

	tmpl := template.Must(template.ParseFiles("templates/discussions.html"))
	tmpl.Execute(w, data)
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

	replies, err := GetRepliesByDiscussionID(db, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	discussion.Replies = BuildReplyTree(replies)

	var avatar string
	data := struct {
		Discussion   Discussion
		DiscussionID string
		Avatar       string
	}{
		discussion,
		id,
		avatar,
	}

	tmplFuncs := template.FuncMap{
		"hexSlice": func(hex string, start, end int) string {
			if start >= 0 && start < len(hex) && end >= 0 && end <= len(hex) && start < end {
				return hex[start:end]
			}
			return ""
		},
	}

	tmpl := template.Must(template.New("discussion.html").Funcs(tmplFuncs).ParseFiles("templates/discussion.html"))
	tmpl.Execute(w, data)
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
	var discriminator int
	err = db.QueryRow("SELECT id, email, username, discriminator, avatar FROM users WHERE email = ?", userEmail).Scan(
		&currentUser.ID,
		&currentUser.Email,
		&currentUser.Profile.Username,
		&discriminator,
		&currentUser.Profile.Avatar,
	)
	if err != nil {
		log.Println("error adding user settings: ", err)
	}
	currentUser.Profile.Discriminator = discriminator

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
			currentUser.Profile.Discriminator = rand.Intn(9999)
			if currentUser.Profile.Discriminator < 1000 {
				currentUser.Profile.Discriminator += 1000
			}
		}

		_, err := db.Exec("UPDATE users SET username = ?, discriminator = ? WHERE email = ?", username, currentUser.Profile.Discriminator, userEmail)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		r.ParseMultipartForm(10 << 20)
		file, fileHeader, err := r.FormFile("avatar")
		if err == nil {
			defer file.Close()
			if !isAllowedImageType(fileHeader) {
				http.Error(w, "Unsupported image format", http.StatusBadRequest)
				return
			}

			avatarFilename := fmt.Sprintf("%d_%s_%04d%s", currentUser.ID, currentUser.Profile.Username, currentUser.Profile.Discriminator, filepath.Ext(fileHeader.Filename))
			currentUser.Profile.Avatar = avatarFilename

			f, err := os.OpenFile("templates/static/avatars/"+avatarFilename, os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer f.Close()
			// io.Copy(f, file)
			if err := resizeImage(file, f, 1<<20, 512); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			_, err = db.Exec("UPDATE users SET avatar = ? WHERE email = ?", avatarFilename, userEmail)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/discussions", http.StatusSeeOther)
	}
}

func setup(w http.ResponseWriter, r *http.Request) {
	db := dbPool.Get().(*sql.DB)
	defer dbPool.Put(db)

	if r.Method == "POST" {
		forumName := r.FormValue("forum_name")
		forumDescription := r.FormValue("forum_description")
		forumContactEmail := r.FormValue("forum_contact_email")
		forumURL := r.FormValue("forum_url")

		_, err := db.Exec(`
					INSERT OR REPLACE INTO config (key, value)
					VALUES ('forum_name', ?), ('forum_description', ?), ('forum_contact_email', ?), ('forum_url', ?), ('setup_completed', '1')
			`, forumName, forumDescription, forumContactEmail, forumURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/setup.html"))
	tmpl.Execute(w, nil)
}
