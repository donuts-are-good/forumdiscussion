package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/mail"
	"regexp"
	"strings"

	"sync"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/nfnt/resize"
	"golang.org/x/crypto/bcrypt"
)

var dbPool *sync.Pool
var port string

var tmpl = template.Must(template.ParseFiles(
	"templates/index.html",
	"templates/login.html",
	"templates/register.html",
	"templates/404.html"))

func main() {
	flag.StringVar(&port, "port", "8080", "Port on which the server listens")
	flag.Parse()

	dbPool = &sync.Pool{
		New: func() interface{} {
			db, err := sqlx.Open("sqlite3", "file:sqlite.db?cache=shared")
			if err != nil {
				log.Fatal("Failed to create a new connection:", err)
			}
			err = ensureTablesPresent(db)
			if err != nil {
				log.Fatal("Failed to ensure tables are present:", err)
			}
			return db
		},
	}

	r := mux.NewRouter()
	r.HandleFunc("/", index)
	r.HandleFunc("/login", login)
	r.HandleFunc("/register", register)
	r.HandleFunc("/discussions", discussions)
	r.HandleFunc("/discussion/{id}", discussion)
	r.HandleFunc("/new_discussion", newDiscussion)
	r.HandleFunc("/new_reply/{discussionID}", newReply)
	r.HandleFunc("/settings", settings)
	r.HandleFunc("/setup", setup)

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/",
		http.FileServer(http.Dir("templates/static/"))))
	r.NotFoundHandler = http.HandlerFunc(notFoundHandler)

	http.ListenAndServe(":"+port, r)
}

func BuildReplyTree(replies []*Reply) []*Reply {
	replyMap := make(map[int]*Reply)
	for _, reply := range replies {
		replyMap[reply.ID] = reply
	}
	var rootReplies []*Reply
	for _, reply := range replies {
		if reply.ParentID == nil {
			rootReplies = append(rootReplies, reply)
		} else {
			parentReply := replyMap[*reply.ParentID]
			parentReply.Children = append(parentReply.Children, reply)
		}
	}
	return rootReplies
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

func isAllowedImageType(fileHeader *multipart.FileHeader) bool {
	allowedMimeTypes := []string{
		"image/jpeg",
		"image/png",
		"image/gif",
	}

	for _, mimeType := range allowedMimeTypes {
		if fileHeader.Header.Get("Content-Type") == mimeType {
			return true
		}
	}
	return false
}

func resizeImage(src io.Reader, dst io.Writer, maxSize int, maxDimensions int) error {
	img, format, err := image.Decode(src)
	if err != nil {
		return err
	}

	if img.Bounds().Dx() > maxDimensions || img.Bounds().Dy() > maxDimensions {
		img = resize.Resize(uint(maxDimensions), 0, img, resize.Lanczos3)
	}

	switch strings.ToLower(format) {
	case "jpeg", "jpg":
		return jpeg.Encode(dst, img, &jpeg.Options{Quality: 75})
	case "png":
		return png.Encode(dst, img)
	default:
		return fmt.Errorf("unsupported image format: %s", format)
	}
}
