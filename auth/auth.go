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
	err = stmt.QueryRow(email).Scan(&user.ID, &user.Name, &user.Email, &user.Password)
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

	stmt, err := config.DB.Prepare("INSERT INTO users (id, name, email, password) VALUES ($1, $2, $3, $4);")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.ID, user.Name, user.Email, user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("User created successfully"))
}

func LoginUser(email string, password string) {

}
