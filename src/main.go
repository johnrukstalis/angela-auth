package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"

	"github.com/retroruk/centralized-devops-auth/src/controllers"
	"github.com/retroruk/centralized-devops-auth/src/services"
)

func main() {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSLMODE"),
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Cannot connect to database:", err)
	}

	mux := http.NewServeMux()

	controllers.InitKeycloakController(mux, services.InitKeycloakService(db))

	log.Println("Server started on port 5001")
	if err := http.ListenAndServe(":5001", mux); err != nil {
		log.Fatal("failed to start server", err)
	}
}
