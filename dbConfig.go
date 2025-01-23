package main

import (
	"database/sql"
	"fmt"
	"os"
)

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

var DB *sql.DB

func getDB() error {
	connectionString := os.Getenv("DB_CONNECTION_STRING")
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return err
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		return err
	}

	fmt.Println("Successfully connected to database!")

	DB = db
	return nil
}

func insertUser(user User) error {
	stmt, err := DB.Prepare("INSERT INTO users (name, email, password) VALUES ($1, $2, $3)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.Name, user.Email, user.Password)
	if err != nil {
		return err
	}

	return nil
}
