package main

import (
    "fmt"
    "net/http"
)

func main() {

    serveMux := http.NewServeMux()

    //serveMux.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {
    //    http.NotFound(resp, req)
    //})

    serveMux.Handle("/", http.FileServer(http.Dir(".")))
    serveMux.Handle("/assets", http.FileServer(http.Dir("./assets")))

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
