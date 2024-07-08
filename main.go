package main

import (
    "fmt"
    "net/http"
    "encoding/json"
    "strings"
    "os"
)

type apiConfig struct {
    fileserverHits int
}

func (conf *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
    return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
        conf.fileserverHits ++
        next.ServeHTTP(resp, req)
    })
}

func (conf *apiConfig) reset() {
    conf.fileserverHits = 0
}

var currentChirpId int = 1 

type Chirp struct {
    Id int `json:"id"`
    Text string `json:"body"`
}

var db []Chirp = nil

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

func handlePost(resp http.ResponseWriter, req *http.Request) {
    type parameters struct {
        Body string `json:"body"`
    }

    type returnVals struct {
        Error string `json:"error"`
        Valid bool `json:"valid"`
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
        Id: currentChirpId,
    }

    dat, err := json.Marshal(chirp)
    if err != nil {
        return
    }
    
    purified := purify(params.Body)
    
    chirp.Text= purified

    resp.WriteHeader(status)
    resp.Header().Set("Content-Type", "application/json") 
    resp.Write(dat)

    // Save file
    currentChirpId++

    initDb()
    db = append(db, chirp)
    saveDb()
}

func initDb() {
    if db != nil {
        return
    }

    db := []Chirp{}

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

func purify(ch string) string {
    badWords := []string {
        "kerfuffle",
        "sharbert",
        "fornax",
    }
    
    words := strings.Split(ch, " ")
    newWords := []string {}
    
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

    serveMux.HandleFunc("POST /api/chirps", handlePost)
    serveMux.HandleFunc("GET /api/chirps", handleGet)

    serveMux.Handle("/*", http.StripPrefix("/app", cfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))

    server := http.Server{ 
        Addr: "0.0.0.0:8080",
        Handler: serveMux,
    }
    err := server.ListenAndServe()

    if err != nil {
        fmt.Println("Error: ", err)
    }

    fmt.Println("Hello, world!")
}
