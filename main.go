package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"swiftpick.com/m/v2/auth"
	"swiftpick.com/m/v2/config"
)

func main() {
	enverr := godotenv.Load()
	if enverr != nil {
		log.Fatal("Error loading .env file")
	}
	fmt.Println("Starting server http://localhost:8080/")
	err := config.InitDB()
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer config.DB.Close()
	http.HandleFunc("POST /user", auth.SignUpUser)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
