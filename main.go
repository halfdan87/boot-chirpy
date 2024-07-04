package main

import (
    "fmt"
    "net/http"
)

func main() {

    serveMux := http.NewServeMux()

    serveMux.HandleFunc("/healthz", func(resp http.ResponseWriter, req *http.Request) {
        resp.Header()["Content-Type"] = []string{"text/plain; charset=utf-8"}
        resp.WriteHeader(200)
        resp.Write([]byte("OK"))
    })

    serveMux.Handle("/", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
    serveMux.Handle("/assets", http.StripPrefix("/app", http.FileServer(http.Dir("./assets"))))

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
