package certreloader_test

import (
    "crypto/tls"
    "log"
    "net/http"
    "time"

    "github.com/zhangyoufu/certreloader"
)

func Example() {
    const (
        listenAddr = "localhost:8443"
        certPath = "path/to/fullchain.pem"
        keyPath = "path/to/privkey.pem"
        reloadInterval = 5 * time.Minute
    )

    reloader, err := certreloader.New(certPath, keyPath, reloadInterval)
    if err != nil {
        // unable to load certificate / private key
        log.Fatal(err)
    }
    server := http.Server {
        Addr: listenAddr,
        TLSConfig: &tls.Config {
            GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
                return reloader.Get(), nil
            },
        },
    }
    err = server.ListenAndServeTLS("", "")
    log.Fatal(err)
}
