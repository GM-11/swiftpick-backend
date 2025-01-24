package auth

import (
	"encoding/json"
	"net/http"

	"swiftpick.com/m/v2/config"
)

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

	if user.Password != password {
		http.Error(w, "Incorrect password", http.StatusBadRequest)
		return
	}

	userJson, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(userJson)

}
