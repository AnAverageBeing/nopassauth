package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/AnAverageBeing/nopassauth/auth"
	"github.com/AnAverageBeing/nopassauth/database"
	"github.com/joho/godotenv"
	"github.com/juju/ratelimit"
)

type RegisterRequest struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

type LoginRequest struct {
	Username string `json:"username"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Message string `json:"message"`
	Token   []byte `json:"token"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Failed to load .env file: %v", err)
	}

	jwtSecret := []byte(os.Getenv("JWT_SECRET_KEY"))

	// Create a database instance
	db, err := database.NewSQLiteDB(os.Getenv("DB_PATH"))
	if err != nil {
		log.Fatalln(err)
	}

	// Create the authentication engine
	authEngine, err := auth.NewAuthEngine(jwtSecret, db)
	if err != nil {
		log.Fatalf("Failed to create AuthEngine: %v", err)
	}

	// Set up rate limiting
	limiter := ratelimit.NewBucket(time.Second, 10) // Allow 10 requests per second

	// Register endpoint
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		// Apply rate limiting
		if limiter.TakeAvailable(1) == 0 {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			log.Println("Rate limit exceeded")
			return
		}

		// Parse the JSON request body
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			log.Printf("Failed to decode register request: %v", err)
			return
		}

		// Register the user
		token, err := authEngine.RegisterUser(req.Username, req.PublicKey)
		if err != nil {
			response := ErrorResponse{Error: err.Error()}
			log.Printf("Failed to register user '%s': %v", req.Username, err)
			jsonResponse(w, http.StatusInternalServerError, response)
			return
		}

		log.Printf("User '%s' registered successfully", req.Username)

		// Return success response
		response := SuccessResponse{
			Message: "User registered successfully",
			Token:   token,
		}
		jsonResponse(w, http.StatusOK, response)
	})

	// Login endpoint
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Apply rate limiting
		if limiter.TakeAvailable(1) == 0 {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			log.Println("Rate limit exceeded")
			return
		}

		// Parse the JSON request body
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			log.Printf("Failed to decode login request: %v", err)
			return
		}

		// Login the user and get the encrypted token
		token, err := authEngine.LoginUser(req.Username)
		if err != nil {
			response := ErrorResponse{Error: err.Error()}
			log.Printf("Failed to log in user '%s': %v", req.Username, err)
			jsonResponse(w, http.StatusUnauthorized, response)
			return
		}

		log.Printf("User '%s' logged in successfully", req.Username)

		// Return success response
		response := SuccessResponse{
			Message: "User logged in successfully",
			Token:   token,
		}
		jsonResponse(w, http.StatusOK, response)
	})

	// Start the server
	log.Println("Server listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func jsonResponse(w http.ResponseWriter, statusCode int, response interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}
