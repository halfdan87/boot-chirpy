package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/halfdan87/boot-chirpy/internal/database"
	"github.com/joho/godotenv"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits int
	jwtSecret      string
	queries        *database.Queries
	platform       string
}

func (conf *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		conf.fileserverHits++
		next.ServeHTTP(resp, req)
	})
}

func (conf *apiConfig) reset() {
	conf.fileserverHits = 0
}

var currentChirpId int = 1
var currentUserId int = 1

type Chirp struct {
	Id        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Text      string    `json:"body"`
	UserId    string    `json:"user_id"`
}

type User struct {
	Id          string    `json:"id"`
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Password    string    `json:"password"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

type RefreshToken struct {
	UserId    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

var db []Chirp = nil
var userDb []User = nil
var tokenDb []RefreshToken = nil

func (s RefreshToken) isExpired() bool {
	return s.ExpiresAt.After(time.Now())
}

func createRefreshToken(userId string) string {
	randomKey := make([]byte, 256)
	rand.Read(randomKey)

	hexStr := hex.EncodeToString(randomKey)

	tok := RefreshToken{
		UserId:    userId,
		Token:     hexStr,
		ExpiresAt: time.Now(),
	}
	tokenDb = append(tokenDb, tok)
	return hexStr
}

func getTokenFromDb(token string) RefreshToken {
	for i := range len(tokenDb) {
		if tokenDb[i].Token == token {
			if tokenDb[i].isExpired() {
				tokenDb = append(tokenDb[:i], tokenDb[i+1:]...)
				return RefreshToken{}
			}
			return tokenDb[i]
		}
	}
	return RefreshToken{}
}

func revokeToken(token string) {
	for i := range len(tokenDb) {
		if token == tokenDb[i].Token {
			tokenDb = append(tokenDb[:i], tokenDb[i+1:]...)
		}
	}
}

type ById []Chirp

func (a ById) Len() int           { return len(a) }
func (a ById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ById) Less(i, j int) bool { return a[i].Id < a[j].Id }

type ByIdDesc []Chirp

func (a ByIdDesc) Len() int           { return len(a) }
func (a ByIdDesc) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByIdDesc) Less(i, j int) bool { return a[i].Id > a[j].Id }

func getHandleGetAllChirps(cfg *apiConfig) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		chirps, err := cfg.queries.GetAllChirpsInAscendingOrder(req.Context())
		if err != nil {
			fmt.Println("Error getting all chirps: ", err)
			resp.WriteHeader(500)
			return
		}

		jsonChirps := []Chirp{}
		for _, chirp := range chirps {
			jsonChirps = append(jsonChirps, dbChirpToJson(chirp))
		}

		dat, err := json.Marshal(jsonChirps)
		if err != nil {
			return
		}

		resp.WriteHeader(200)
		resp.Header().Set("Content-Type", "application/json")
		resp.Write(dat)
	}
}

func deleteChirp(chirpId int, owner User) bool {
	// handle in db
	return false
}

func getHandleGetWithParams(cfg *apiConfig) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		chirpId := req.PathValue("chirpId")

		parsedUUID, err := uuid.Parse(chirpId)
		if err != nil {
			fmt.Println("Error parsing chirp ID: ", err)
			resp.WriteHeader(500)
			return
		}
		dbChirp, err := cfg.queries.GetChirpByID(req.Context(), parsedUUID)
		if err != nil {
			fmt.Println("Error getting chirp by ID: ", err)
			resp.WriteHeader(500)
			return
		}

		if dbChirp == (database.Chirp{}) {
			resp.WriteHeader(404)
			return
		}

		jsonChirp := dbChirpToJson(dbChirp)

		dat, err := json.Marshal(jsonChirp)
		if err != nil {
			return
		}
		resp.WriteHeader(200)
		resp.Header().Set("Content-Type", "application/json")
		resp.Write(dat)
		return
	}
}

func getHandlePostChirp(cfg *apiConfig) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		type parameters struct {
			UserId string `json:"user_id"`
			Body   string `json:"body"`
		}

		/*
			jwtHeader := req.Header.Get("Authorization")
			if jwtHeader == "" {
				fmt.Println("Authorization header is not provided")
				resp.WriteHeader(401)
				return
			}

			jwtSecret := cfg.jwtSecret
			jwtHeader = strings.TrimPrefix(jwtHeader, "Bearer ")

			token, err := jwt.ParseWithClaims(jwtHeader, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(jwtSecret), nil
			})

			fmt.Println(jwtHeader)

			if err != nil {
				fmt.Printf("Could not parse token: %v %v\n", err, jwtHeader)
				resp.WriteHeader(401)
				return
			}

			claims, ok := token.Claims.(*jwt.RegisteredClaims)
			if !ok || !token.Valid {
				fmt.Println("Invalid token")
				resp.WriteHeader(401)
				return
			}

			if claims.ExpiresAt != nil && !claims.ExpiresAt.After(time.Now()) {
				fmt.Println("Expired token")
				resp.WriteHeader(401)
				return
			}

			userId := claims.Subject
			id, err := strconv.Atoi(userId)
			if err != nil {
				fmt.Println("Invalid user ID in token:", userId)
				resp.WriteHeader(401)
				return
			}

		*/

		decoder := json.NewDecoder(req.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			resp.WriteHeader(500)
			return
		}

		status := 201
		if len(params.Body) > 140 {
			status = 400
		}

		userUUID, err := uuid.Parse(params.UserId)
		if err != nil {
			fmt.Println("Error parsing user ID: ", err)
			resp.WriteHeader(500)
			return
		}

		purified := purify(params.Body)
		createParams := database.CreateChirpParams{
			UserID: userUUID,
			Body:   purified,
		}
		dbChirp, err := cfg.queries.CreateChirp(req.Context(), createParams)
		if err != nil {
			fmt.Println("Error creating chirp: ", err)
			resp.WriteHeader(500)
			return
		}

		chirp := dbChirpToJson(dbChirp)

		dat, err := json.Marshal(chirp)
		if err != nil {
			return
		}

		resp.WriteHeader(status)
		resp.Header().Set("Content-Type", "application/json")
		resp.Write(dat)
	}
}

func handleDeleteChirp(resp http.ResponseWriter, req *http.Request) {
	chirpId, _ := strconv.Atoi(req.PathValue("chirpId"))

	type returnVals struct {
		Error       string `json:"error"`
		Valid       bool   `json:"valid"`
		CleanedBody string `json:"cleaned_body"`
	}

	jwtHeader := req.Header.Get("Authorization")
	if jwtHeader == "" {
		fmt.Println("Authorization header is not provided")
		resp.WriteHeader(401)
		return
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	jwtHeader = strings.TrimPrefix(jwtHeader, "Bearer ")

	token, err := jwt.ParseWithClaims(jwtHeader, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	fmt.Println(jwtHeader)

	if err != nil {
		fmt.Printf("Could not parse token: %v %v\n", err, jwtHeader)
		resp.WriteHeader(401)
		return
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		fmt.Println("Invalid token")
		resp.WriteHeader(401)
		return
	}

	if claims.ExpiresAt != nil && !claims.ExpiresAt.After(time.Now()) {
		fmt.Println("Expired token")
		resp.WriteHeader(401)
		return
	}

	userId := claims.Subject
	id, err := strconv.Atoi(userId)
	if err != nil {
		fmt.Println("Invalid user ID in token:", userId)
		resp.WriteHeader(401)
		return
	}

	user := findUserById(id)
	if user == (User{}) {
		respBody := returnVals{
			Error: "User does not exist",
		}

		dat, err := json.Marshal(respBody)
		if err != nil {
			return
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(500)
		resp.Write(dat)
		return
	}

	initDb()

	status := 403
	if deleteChirp(chirpId, user) {
		status = 204
	}

	resp.WriteHeader(status)

	saveDb()
}

func getHandlePostUser(cfg *apiConfig) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		type parameters struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}

		type returnVals struct {
			Error       string `json:"error"`
			Valid       bool   `json:"valid"`
			CleanedBody string `json:"cleaned_body"`
		}

		decoder := json.NewDecoder(req.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			respBody := returnVals{
				Error: "Error decoding json",
			}

			dat, err := json.Marshal(respBody)
			if err != nil {
				return
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(500)
			resp.Write(dat)
			return
		}

		user, err := cfg.queries.CreateUser(req.Context(), params.Email)
		if err != nil {
			fmt.Println("Error creating user: ", err)
			resp.WriteHeader(500)
			return
		}

		status := 201

		jsonUser := dbUserToJson(user)
		dat, err := json.Marshal(jsonUser)
		if err != nil {
			return
		}

		resp.WriteHeader(status)
		resp.Header().Set("Content-Type", "application/json")
		resp.Write(dat)
	}
}

func handlePostPolkaWebhook(resp http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserId int `json:"user_id"`
		} `json:"data"`
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		fmt.Println("Authorization header is not provided")
		resp.WriteHeader(401)
		return
	}

	authHeader = strings.TrimPrefix(authHeader, "ApiKey ")

	polkaApiKey := os.Getenv("POLKA_API_KEY")

	if authHeader != polkaApiKey {
		fmt.Println("Authorization header is not correct")
		resp.WriteHeader(401)
		return
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println("Ilformed body")
		resp.WriteHeader(404)
		return
	}

	if params.Event != "user.upgraded" {
		fmt.Println("Unsupported event")
		resp.WriteHeader(204)
		return
	}

	fmt.Printf("Search by id: %v\n", params.Data.UserId)

	found := findUserById(params.Data.UserId)
	if found == (User{}) {
		fmt.Println("User not found")
		resp.WriteHeader(404)
		return
	}

	initUserDb()

	found.IsChirpyRed = true
	updateUser(found)
	resp.WriteHeader(204)

	saveUserDb()
}

func handlePutUser(resp http.ResponseWriter, req *http.Request) {
	fmt.Println("Put user")
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	type returnVals struct {
		Error       string `json:"error"`
		Valid       bool   `json:"valid"`
		CleanedBody string `json:"cleaned_body"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respBody := returnVals{
			Error: "Error decoding json",
		}

		dat, err := json.Marshal(respBody)
		if err != nil {
			return
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(500)
		resp.Write(dat)
		return
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		fmt.Println("JWT_SECRET environment variable is not set")
		resp.WriteHeader(500)
		return
	}

	jwtHeader := req.Header.Get("Authorization")
	if jwtHeader == "" {
		fmt.Println("Authorization header is not provided")
		resp.WriteHeader(401)
		return
	}

	jwtHeader = strings.TrimPrefix(jwtHeader, "Bearer ")

	token, err := jwt.ParseWithClaims(jwtHeader, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	fmt.Println(jwtHeader)

	if err != nil {
		fmt.Printf("Could not parse token: %v %v\n", err, jwtHeader)
		resp.WriteHeader(401)
		return
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		fmt.Println("Invalid token")
		resp.WriteHeader(401)
		return
	}

	if claims.ExpiresAt != nil && !claims.ExpiresAt.After(time.Now()) {
		fmt.Println("Expired token")
		resp.WriteHeader(401)
		return
	}

	userId := claims.Subject
	id, err := strconv.Atoi(userId)
	if err != nil {
		fmt.Println("Invalid user ID in token:", userId)
		resp.WriteHeader(401)
		return
	}

	user := findUserById(id)
	if user == (User{}) {
		respBody := returnVals{
			Error: "User does not exist",
		}

		dat, err := json.Marshal(respBody)
		if err != nil {
			return
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(500)
		resp.Write(dat)
		return
	}

	user.Email = params.Email

	dat, err := json.Marshal(user)
	if err != nil {
		return
	}

	resp.WriteHeader(200)
	resp.Header().Set("Content-Type", "application/json")
	resp.Write(dat)

	cryptedPassword, _ := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
	user.Password = string(cryptedPassword)

	initUserDb()
	updateUser(user)
	saveUserDb()
	fmt.Println("END Put user")
}

func updateUser(user User) {
	initUserDb()

	for i := range userDb {
		if userDb[i].Id == user.Id {
			userDb[i].Email = user.Email
			userDb[i].Password = user.Password
			userDb[i].IsChirpyRed = user.IsChirpyRed
			return
		}
	}
}

func findUserByEmail(email string) User {
	initUserDb()

	for _, user := range userDb {
		if user.Email == email {
			return user
		}
	}
	return User{}
}

func findUserById(id int) User {
	// TODO: This should be done in the database
	return User{}
}

func handleLogin(resp http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Password         string `json:"password"`
		Email            string `json:"email"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}

	type returnVals struct {
		Id           string `json:"id"`
		Email        string `json:"email"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		IsChirpyRed  bool   `json:"is_chirpy_red"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println("Error decoding params: " + err.Error())
		resp.WriteHeader(500)
		return
	}

	user := findUserByEmail(params.Email)
	if user == (User{}) {
		fmt.Println("Couldnt find user by email " + params.Email)
		resp.WriteHeader(500)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(params.Password))
	if err != nil {
		resp.WriteHeader(401)
		return
	}

	jwtSecret := []byte(os.Getenv("JWT_SECRET"))

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Issuer:    "chirpy",
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(1) * time.Hour).UTC()),
			Subject:   user.Id,
		},
	)

	signedToken, _ := token.SignedString(jwtSecret)

	refresher := createRefreshToken(user.Id)

	fmt.Println(refresher)

	respData := returnVals{
		Id:           user.Id,
		Email:        user.Email,
		Token:        signedToken,
		RefreshToken: refresher,
		IsChirpyRed:  user.IsChirpyRed,
	}

	fmt.Println(respData)

	reDat, err := json.Marshal(respData)
	if err != nil {
		return
	}

	resp.WriteHeader(200)
	resp.Header().Set("Content-Type", "application/json")
	resp.Write(reDat)
}

func handleRefresh(resp http.ResponseWriter, req *http.Request) {
	type returnVals struct {
		Token string `json:"token"`
	}

	refresher := req.Header.Get("Authorization")
	if refresher == "" {
		fmt.Println("Authorization header is not provided")
		resp.WriteHeader(401)
		return
	}

	refresher = strings.TrimPrefix(refresher, "Bearer ")

	refreshToken := getTokenFromDb(refresher)

	if refreshToken == (RefreshToken{}) {
		fmt.Println("Token invalid")
		resp.WriteHeader(401)
		return
	}

	jwtSecret := []byte(os.Getenv("JWT_SECRET"))

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Issuer:    "chirpy",
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(1) * time.Hour).UTC()),
			Subject:   refreshToken.UserId,
		},
	)

	signedToken, _ := token.SignedString(jwtSecret)

	respData := returnVals{
		Token: signedToken,
	}

	reDat, err := json.Marshal(respData)
	if err != nil {
		return
	}

	resp.WriteHeader(200)
	resp.Header().Set("Content-Type", "application/json")
	resp.Write(reDat)
}

func handleRevoke(resp http.ResponseWriter, req *http.Request) {
	refresher := req.Header.Get("Authorization")
	if refresher == "" {
		fmt.Println("Authorization header is not provided")
		resp.WriteHeader(401)
		return
	}

	refresher = strings.TrimPrefix(refresher, "Bearer ")

	revokeToken(refresher)

	resp.WriteHeader(204)
}

func initUserDb() {
	if userDb != nil {
		return
	}

	userDb = []User{}

	// TODO This should be not Create, because it creates or truncates the file every time
	// But for testing this is cool
	file, err := os.Create("database-user.json")
	if err != nil {
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&userDb)

	if err != nil {
		fmt.Println("Db did not exist yet.", err)
		return
	}
}

func initDb() {
	if db != nil {
		return
	}

	db = []Chirp{}

	file, err := os.Create("database.json")
	if err != nil {
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&db)

	if err != nil {
		fmt.Println("Error ", err)
		return
	}
}

func saveDb() {
	file, err := os.Create("database.json")
	if err != nil {
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(&db)
	if err != nil {
		fmt.Println("Error ", err)
		return
	}
}

func saveUserDb() {
	file, err := os.Create("database-user.json")
	if err != nil {
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(&userDb)
	if err != nil {
		fmt.Println("Error ", err)
		return
	}
}

func purify(ch string) string {
	badWords := []string{
		"kerfuffle",
		"sharbert",
		"fornax",
	}

	words := strings.Split(ch, " ")
	newWords := []string{}

	for _, word := range words {
		isBad := false
		for _, badWord := range badWords {
			if badWord == word || strings.ToLower(word) == badWord {
				isBad = true
				break
			}
		}
		if isBad {
			newWords = append(newWords, "****")
		} else {
			newWords = append(newWords, word)
		}
	}

	return strings.Join(newWords, " ")
}

func main() {
	cfg := apiConfig{}

	serveMux := http.NewServeMux()

	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	cfg.jwtSecret = jwtSecret

	dbUrl := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		fmt.Println("Error connecting to database: ", err)
		return
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		fmt.Println("Error pinging database: ", err)
		return
	}

	cfg.queries = database.New(db)

	platform := os.Getenv("PLATFORM")
	cfg.platform = platform

	serveMux.HandleFunc("GET /api/healthz", func(resp http.ResponseWriter, req *http.Request) {
		resp.Header()["Content-Type"] = []string{"text/plain; charset=utf-8"}
		resp.WriteHeader(200)
		resp.Write([]byte("OK"))
	})

	serveMux.HandleFunc("POST /api/healthz", func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(405)
	})

	serveMux.HandleFunc("/admin/reset", func(resp http.ResponseWriter, req *http.Request) {
		if cfg.platform != "dev" {
			resp.WriteHeader(403)
			return
		}

		err := cfg.queries.DeleteAllUsers(req.Context())
		if err != nil {
			fmt.Println("Error deleting all users: ", err)
			resp.WriteHeader(500)
			return
		}

		cfg.reset()
		resp.Header()["Content-Type"] = []string{"text/plain; charset=utf-8"}
		resp.WriteHeader(200)
		resp.Write([]byte("OK"))
	})

	serveMux.HandleFunc("GET /admin/metrics", func(resp http.ResponseWriter, req *http.Request) {
		resp.Header()["Content-Type"] = []string{"text/html"}
		resp.WriteHeader(200)
		resp.Write([]byte(fmt.Sprintf(`
            <html>
                <body>
                    <h1>Welcome, Chirpy Admin</h1>
                    <p>Chirpy has been visited %d times!</p>
                </body>
            </html>
        `, cfg.fileserverHits)))
	})

	serveMux.HandleFunc("POST /api/chirps", getHandlePostChirp(&cfg))
	serveMux.HandleFunc("DELETE /api/chirps/{chirpId}", handleDeleteChirp)
	serveMux.HandleFunc("GET /api/chirps", getHandleGetAllChirps(&cfg))
	serveMux.HandleFunc("GET /api/chirps/{chirpId}", getHandleGetWithParams(&cfg))

	serveMux.HandleFunc("POST /api/users", getHandlePostUser(&cfg))
	serveMux.HandleFunc("PUT /api/users", handlePutUser)
	serveMux.HandleFunc("POST /api/login", handleLogin)
	serveMux.HandleFunc("POST /api/refresh", handleRefresh)
	serveMux.HandleFunc("POST /api/revoke", handleRevoke)
	serveMux.HandleFunc("POST /api/polka/webhooks", handlePostPolkaWebhook)

	serveMux.Handle("/*", http.StripPrefix("/app", cfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))

	server := http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: serveMux,
	}
	err = server.ListenAndServe()

	if err != nil {
		fmt.Println("Error: ", err)
	}

	fmt.Println("Hello, world!")
}

func dbUserToJson(user database.User) User {
	return User{
		Id:          user.ID.String(),
		Email:       user.Email,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Password:    "",
		IsChirpyRed: false,
	}
}

func dbChirpToJson(chirp database.Chirp) Chirp {
	return Chirp{
		Id:        chirp.ID.String(),
		Text:      chirp.Body,
		UserId:    chirp.UserID.String(),
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
	}
}
