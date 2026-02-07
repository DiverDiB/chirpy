package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/diverdib/chirpy/internal/auth"
	"github.com/diverdib/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var badWords = map[string]struct{}{
	"kerfuffle": {},
	"sharbert":  {},
	"fornax":    {},
}

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecret      string
	polkakey       string
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	const template = `
<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
</html>
`
	w.Write([]byte(fmt.Sprintf(template, cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	// Security Check: Only allow if platform is "dev"
	if cfg.platform != "dev" {
		respondWithError(w, http.StatusForbidden, "Reset is only allowed in dev mode")
		return
	}
	// Database Action: Delete all users
	err := cfg.db.ResetUsers(r.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't reset users")
		return
	}
	// Reset metrics counter
	cfg.fileserverHits.Store(0)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))

}

func (cfg *apiConfig) handlerUsersCreate(w http.ResponseWriter, r *http.Request) {
	params := parameters{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	// Hash the password
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't hash password")
	}

	// Create the user in the dB
	user, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		ID:             uuid.New(),
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create user")
		return
	}

	respondWithJSON(w, http.StatusCreated, databaseUserToUser(user))
}

func (cfg *apiConfig) handlerUpdate(w http.ResponseWriter, r *http.Request) {
	// Extract the token
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find token")
		return
	}

	// Validate the JWT and extract the UserID
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't validate JWT")
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	// Hash the password
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't hash password")
	}

	// Update the user in the dB
	user, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userID,
		UpdatedAt:      time.Now().UTC(),
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't update user")
		return
	}

	// Respond with the updated user
	respondWithJSON(w, http.StatusOK, databaseUserToUser(user))
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	// Look up the user by email
	user, err := cfg.db.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		// Return 401 if user doesn't exist
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	// Compare the provided password with the stored hash
	match, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil || !match {
		// This handles actual system errors
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	expirationDuration := time.Hour

	// Generate the JWT using your Make JWT function
	token, err := auth.MakeJWT(
		user.ID,
		cfg.jwtSecret,
		expirationDuration,
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create JWT")
		return
	}

	// Generate refresh token
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create refresh token")
		return
	}
	_, err = cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().AddDate(0, 0, 60), // 60 days
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't save refresh token")
		return
	}
	// Return the user and the token on success (200 OK)
	respondWithJSON(w, http.StatusOK, response{
		User:         databaseUserToUser(user),
		Token:        token,
		RefreshToken: refreshToken,
	})
}

func (cfg *apiConfig) handlerPolkaWebhooks(w http.ResponseWriter, r *http.Request) {
	// Extract the api key
	GetAPIKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find api key")
		return
	}

	if GetAPIKey != cfg.polkakey {
		respondWithError(w, http.StatusUnauthorized, "api key is invalid")
		return
	}
	decoder := json.NewDecoder(r.Body)
	req := PolkaWebhookRequest{}
	err = decoder.Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't decode parameters")
		return
	}

	// If event is not "user.upgraded", responsd with 204 immediately
	if req.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Attempt to upgrade the user
	err = cfg.db.UpgradeUser(r.Context(), req.Data.UserID)
	if err != nil {
		// If the user isn't found, respond with 404
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "User not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Couldn't upgrade user")
		return
	}
	// Respond with 204 on success
	w.WriteHeader((http.StatusNoContent))

}

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find token")
		return
	}

	user, err := cfg.db.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Token is invalid or expired")
		return
	}

	// Issue a new access token (JWT)
	newToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create JWT")
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]string{
		"token": newToken,
	})
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	// Extract the refresh token from the header
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't find token")
		return
	}

	// Revoke the token in the database
	err = cfg.db.RevokeRefreshToken(r.Context(), database.RevokeRefreshTokenParams{
		Token:     refreshToken,
		RevokedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't revoke token")
		return
	}

	// Respond with 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handlerChirpsCreate(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	// Get the token from the Authorization header
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find JWT")
		return
	}

	// Validate the JWT and extract the UserID
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't validate JWT")
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	// Ported Validation Logic: Check length
	const maxChirpLength = 140
	if len(params.Body) > maxChirpLength {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	// Ported Validation Logic: Clean profanity
	cleanedBody := getCleanedBody(params.Body)

	// Save to Database
	chirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
		ID:        uuid.New(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Body:      cleanedBody,
		UserID:    userID,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create chirp")
		return
	}
	// Respond with 201 Created and the full resource
	respondWithJSON(w, http.StatusCreated, Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	})
}

func (cfg *apiConfig) handlerChirpsGet(w http.ResponseWriter, r *http.Request) {
	authorIDString := r.URL.Query().Get("author_id")
	sortIDString := r.URL.Query().Get("sort")
	if sortIDString != "" && sortIDString != "asc" && sortIDString != "desc" {
		respondWithError(w, http.StatusBadRequest, "Invalid sort parameter")
		return
	}

	var dbChirps []database.Chirp
	var err error

	if authorIDString != "" {
		authorID, parseErr := uuid.Parse(authorIDString)
		if parseErr != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid author ID")
			return
		}
		if sortIDString == "desc" {
			dbChirps, err = cfg.db.GetChirpsForAuthorDesc(r.Context(), authorID)
		} else {
			dbChirps, err = cfg.db.GetChirpsForAuthor(r.Context(), authorID)
		}
	} else {
		if sortIDString == "desc" {
			dbChirps, err = cfg.db.GetChirpsDesc(r.Context())
		} else {
			dbChirps, err = cfg.db.GetChirps(r.Context())
		}
	}
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't retrieve chirps")
		return
	}

	chirps := []Chirp{}
	for _, dbChirp := range dbChirps {
		chirps = append(chirps, Chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
		})
	}

	respondWithJSON(w, http.StatusOK, chirps)
}

func (cfg *apiConfig) handlerChirpGet(w http.ResponseWriter, r *http.Request) {
	chirpIDString := r.PathValue("chirpID")

	// Parse the string into a UUID
	chirpID, err := uuid.Parse(chirpIDString)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
	}

	// Query the database
	dbChirp, err := cfg.db.GetChirp(r.Context(), chirpID)
	if err != nil {
		// Check if error is specifically a missing row
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		// Otherwise, it's a real database problem
		respondWithError(w, http.StatusInternalServerError, "Couldn't retrieve chirp")
		return
	}

	// Respond with 200 OK and the array of chirps
	respondWithJSON(w, http.StatusOK, Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	})
}

func (cfg *apiConfig) handlerChirpDelete(w http.ResponseWriter, r *http.Request) {
	// Get the token from the Authorization header
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find JWT")
		return
	}

	// Validate the JWT and extract the UserID
	UserID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't validate JWT")
		return
	}
	chirpIDString := r.PathValue("chirpID")

	// Parse the string into a UUID
	chirpID, err := uuid.Parse(chirpIDString)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
	}

	// Fetch the chirp first to check owner
	dbChirp, err := cfg.db.GetChirp(r.Context(), chirpID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Chirp not found")
		return
	}
	// Authorization: Does the user own this chirp?
	if dbChirp.UserID != UserID {
		respondWithError(w, http.StatusForbidden, "You can't delete someone else's chirp")
		return
	}

	// Query the database
	err = cfg.db.DeleteChirp(r.Context(), chirpID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't retrieve chirp")
		return
	}

	// Respond with 204 No content
	w.WriteHeader((http.StatusNoContent))
}

type parameters struct {
	Password         string `json:"password"`
	Email            string `json:"email"`
	ExpiresInSeconds *int   `json:"expires_in_seconds"`
}

type errorResponse struct {
	Error string `json:"error"`
}

//type validResponse struct {
//	Valid bool `json:"valid"`
//}

//type returnVals struct {
//	CleanedBody string `json:"cleaned_body"`
//}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	// use "-" to ensure this field is not sent in JSON response
	PasswordHash string `json:"-"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
}

type PolkaWebhookRequest struct {
	Event string `json:"event"`
	Data  struct {
		UserID uuid.UUID `json:"user_id"`
	} `json:"data"`
}

func getCleanedBody(body string) string {
	words := strings.Split(body, " ")
	for i, word := range words {
		loweredWord := strings.ToLower(word)
		_, ok := badWords[loweredWord]
		if ok {
			words[i] = "****"
		}
	}
	return strings.Join(words, " ")
}

func handlerReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func middlewareLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJSON(w, code, errorResponse{
		Error: msg,
	})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func databaseUserToUser(user database.User) User {
	return User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}
}

func main() {
	// Load the environment file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	platform := os.Getenv("PLATFORM")
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL must be set")
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET must be set")
	}
	polkakey := os.Getenv("POLKA_KEY")
	if polkakey == "" {
		log.Fatal("POLKA_KEY must be set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("error opening database: %s", err)
	}

	// Initialize the config struct
	apiCfg := &apiConfig{
		db:        database.New(db),
		platform:  platform,
		jwtSecret: jwtSecret,
		polkakey:  polkakey,
	}
	apiCfg.fileserverHits.Store(0)

	mux := http.NewServeMux()

	// The TURNSTILE (middleware - counts the hits)
	handlerInc := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(handlerInc))

	// Non-fileserver endpoints
	// Handler for health check
	mux.HandleFunc("GET /api/healthz", handlerReadiness)

	// Handler for metrics SCOREBOARD
	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)

	// Handler to metrics RESET
	mux.HandleFunc("POST /admin/reset", apiCfg.handlerReset)

	// Handler to add user
	mux.HandleFunc("POST /api/users", apiCfg.handlerUsersCreate)

	mux.HandleFunc("PUT /api/users", apiCfg.handlerUpdate)

	// Handler to log in user
	mux.HandleFunc("POST /api/login", apiCfg.handlerLogin)

	// Handler to upgrade user
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlerPolkaWebhooks)

	// Handler to get refresh token
	mux.HandleFunc("POST /api/refresh", apiCfg.handlerRefresh)

	// Handler to revoke token
	mux.HandleFunc("POST /api/revoke", apiCfg.handlerRevoke)

	// Handler to create chirp
	mux.HandleFunc("POST /api/chirps", apiCfg.handlerChirpsCreate)

	// Handler to get chirps
	mux.HandleFunc("GET /api/chirps", apiCfg.handlerChirpsGet)

	// Handler to get chirp by ID
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handlerChirpGet)

	// Handler to delete chirp by ID
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handlerChirpDelete)

	// Wrap the mux in the middlware
	wrappedMux := middlewareLog(mux)

	server := &http.Server{
		Addr:    ":8080",
		Handler: wrappedMux,
	}

	server.ListenAndServe()
}
