package config

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func InitDB() error {
	dbname := os.Getenv("DB_NAME")
	dbuser := os.Getenv("DB_USERNAME")
	dbpass := os.Getenv("DB_PASSWORD")
	dbhost := os.Getenv("DB_HOST")

	connectionString := "user=" + dbuser + " password=" + dbpass + " dbname=" + dbname + " sslmode=disable host=" + dbhost + " port=5432"

	fmt.Print(connectionString)

	// connectionString := "user=postgres password=nice1234 dbname=swiftpick sslmode=disable host=localhost port=5432"

	var err error
	DB, err = sql.Open("postgres", connectionString)
	if err != nil {
		return err
	}

	// Test the connection
	if err := DB.Ping(); err != nil {
		return err
	}

	log.Println("Successfully Connected")
	return nil
}

func GetDB() *sql.DB {
	return DB
}
