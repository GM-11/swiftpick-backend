package auth

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"swiftpick.com/m/v2/config"
)

const bcryptCost = 12

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

	userExists, err := checkIfUserExists(user.Email)
	if err != nil {
		w.Write([]byte(err.Error()))
	}

	if userExists {
		w.Write([]byte("User already exists"))
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

	user.Password = ""
	userJson, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(userJson)
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

	user.Password = ""
	userJson, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(userJson)
}
