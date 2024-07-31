package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type apiConfig struct {
	fileserverHits int
	jwtSecret      string
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
	Id   int    `json:"id"`
	Text string `json:"body"`
}

type User struct {
	Id       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

var db []Chirp = nil
var userDb []User = nil

func handleGet(resp http.ResponseWriter, req *http.Request) {
	initDb()

	dat, err := json.Marshal(db)
	if err != nil {
		return
	}

	resp.WriteHeader(200)
	resp.Header().Set("Content-Type", "application/json")
	resp.Write(dat)
}

func handleGetWithParams(resp http.ResponseWriter, req *http.Request) {
	initDb()

	chirpId, _ := strconv.Atoi(req.PathValue("chirpId"))

	for _, chirp := range db {
		if chirp.Id == chirpId {
			dat, err := json.Marshal(chirp)
			if err != nil {
				return
			}
			resp.WriteHeader(200)
			resp.Header().Set("Content-Type", "application/json")
			resp.Write(dat)
			return
		}
	}

	resp.WriteHeader(404)
}

func handlePostChirp(resp http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Body string `json:"body"`
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

	status := 201
	if len(params.Body) > 140 {
		status = 400
	}

	chirp := Chirp{
		Text: params.Body,
		Id:   currentChirpId,
	}

	dat, err := json.Marshal(chirp)
	if err != nil {
		return
	}

	purified := purify(params.Body)

	chirp.Text = purified

	resp.WriteHeader(status)
	resp.Header().Set("Content-Type", "application/json")
	resp.Write(dat)

	// Save file
	currentChirpId++

	initDb()
	db = append(db, chirp)
	saveDb()
}

func handlePostUser(resp http.ResponseWriter, req *http.Request) {
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

	if found := findUserByEmail(params.Email); found != (User{}) {
		respBody := returnVals{
			Error: fmt.Sprintf("User by email %s already exists", params.Email),
		}

		dat, err := json.Marshal(respBody)
		if err != nil {
			return
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(500)
		resp.Write(dat)
		return
	} else {
		fmt.Println("FOund:", found)
	}

	status := 201

	user := User{
		Id:    currentUserId,
		Email: params.Email,
	}

	currentUserId++

	dat, err := json.Marshal(user)
	if err != nil {
		return
	}

	resp.WriteHeader(status)
	resp.Header().Set("Content-Type", "application/json")
	resp.Write(dat)

	// Save file

	cryptedPassword, _ := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
	user.Password = string(cryptedPassword)

	initUserDb()
	userDb = append(userDb, user)
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
	initUserDb()

	for _, user := range userDb {
		if user.Id == id {
			return user
		}
	}
	return User{}
}

func handleLogin(resp http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Password         string `json:"password"`
		Email            string `json:"email"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}

	type returnVals struct {
		Password string `json:"password"`
		Email    string `json:"email"`
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

	expireInSeconds := params.ExpiresInSeconds
	if expireInSeconds == 0 || expireInSeconds > 24*60*60 {
		expireInSeconds = 24 * 60 * 60
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Issuer:    "chirpy",
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expireInSeconds) * time.Second).UTC()),
			Subject:   strconv.Itoa(user.Id),
		},
	)

	signedToken, _ := token.SignedString(jwtSecret)

	user.Token = signedToken

	dat, err := json.Marshal(user)
	if err != nil {
		return
	}

	resp.WriteHeader(200)
	resp.Header().Set("Content-Type", "application/json")
	resp.Write(dat)
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

	serveMux.HandleFunc("GET /api/healthz", func(resp http.ResponseWriter, req *http.Request) {
		resp.Header()["Content-Type"] = []string{"text/plain; charset=utf-8"}
		resp.WriteHeader(200)
		resp.Write([]byte("OK"))
	})

	serveMux.HandleFunc("POST /api/healthz", func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(405)
	})

	serveMux.HandleFunc("/api/reset", func(resp http.ResponseWriter, req *http.Request) {
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

	serveMux.HandleFunc("POST /api/chirps", handlePostChirp)
	serveMux.HandleFunc("GET /api/chirps", handleGet)
	serveMux.HandleFunc("GET /api/chirps/{chirpId}", handleGetWithParams)

	serveMux.HandleFunc("POST /api/users", handlePostUser)
	serveMux.HandleFunc("PUT /api/users", handlePutUser)
	serveMux.HandleFunc("POST /api/login", handleLogin)

	serveMux.Handle("/*", http.StripPrefix("/app", cfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))

	server := http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: serveMux,
	}
	err := server.ListenAndServe()

	if err != nil {
		fmt.Println("Error: ", err)
	}

	fmt.Println("Hello, world!")
}
