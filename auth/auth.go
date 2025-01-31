package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"swiftpick.com/m/v2/config"
)

const (
	bcryptCost      = 12
	tokenExpiration = time.Hour * 24 // 24 hours
)

var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func checkIfUserExists(email string) (bool, error) {
	stmt, err := config.DB.Prepare("SELECT * FROM users WHERE email = $1;")
	if err != nil {
		return false, err
	}
	defer stmt.Close()

	var user config.User
	err = stmt.QueryRow(email).Scan(&user.Name, &user.Email, &user.Password)
	if err != nil {
		return false, err
	}
	return true, nil
}

func SignUpUser(w http.ResponseWriter, r *http.Request) {
	user := config.User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userExists, err := checkIfUserExists(user.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if userExists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	user.Password = hashedPassword

	stmt, err := config.DB.Prepare("INSERT INTO users (name, email, password) VALUES ($1, $2, $3);")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.Name, user.Email, user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := generateToken(user.Email)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	type Response struct {
		User  config.User `json:"user"`
		Token string      `json:"token"`
	}

	user.Password = "" // Remove password from response
	response := Response{
		User:  user,
		Token: token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func LoginUser(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	stmt, err := config.DB.Prepare("SELECT * FROM users WHERE email = $1;")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	var user config.User
	err = stmt.QueryRow(email).Scan(&user.Name, &user.Email, &user.Password)
	if err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	if !checkPasswordHash(password, user.Password) {
		http.Error(w, "Incorrect password", http.StatusBadRequest)
		return
	}

	token, err := generateToken(user.Email)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	type Response struct {
		User  config.User `json:"user"`
		Token string      `json:"token"`
	}

	user.Password = "" // Remove password from response
	response := Response{
		User:  user,
		Token: token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func generateToken(email string) (string, error) {
	expirationTime := time.Now().Add(tokenExpiration)
	claims := &Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func VerifyToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrInvalidKey
	}

	return claims, nil
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized: No token provided", http.StatusUnauthorized)
			return
		}

		// Remove "Bearer " prefix if present
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		claims, err := VerifyToken(tokenString)
		if err != nil {
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to request context
		r = r.WithContext(context.WithValue(r.Context(), "email", claims.Email))
		next.ServeHTTP(w, r)
	}
}
