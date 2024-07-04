package main

import (
    "fmt"
    "net/http"
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

func main() {
    cfg := apiConfig{}

    serveMux := http.NewServeMux()

    serveMux.HandleFunc("/healthz", func(resp http.ResponseWriter, req *http.Request) {
        resp.Header()["Content-Type"] = []string{"text/plain; charset=utf-8"}
        resp.WriteHeader(200)
        resp.Write([]byte("OK"))
    })

    serveMux.HandleFunc("/metrics", func(resp http.ResponseWriter, req *http.Request) {
        resp.Header()["Content-Type"] = []string{"text/plain; charset=utf-8"}
        resp.WriteHeader(200)
        resp.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits)))
    })

    serveMux.HandleFunc("/reset", func(resp http.ResponseWriter, req *http.Request) {
        cfg.reset()
        resp.Header()["Content-Type"] = []string{"text/plain; charset=utf-8"}
        resp.WriteHeader(200)
        resp.Write([]byte("OK"))
    })

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
