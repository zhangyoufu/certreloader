// Package certreloader implements a periodic X.509 certificate reloader.
package certreloader

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"sync/atomic"
	"time"
	"unsafe"
)

// Reloader converts X.509 certificate and private key in PEM format to
// tls.Certificate. It periodically checks their contents in background, and
// tries to reload atomically when changes were detected. Reload failure will
// be logged and will not break previously loaded one.
type Reloader struct {
	certPath string
	keyPath  string
	certPEM  []byte
	keyPEM   []byte // BUG: plaintext private key left in memory
	cert     *tls.Certificate
	chStop   chan struct{}
}

// New return a new Reloader. The path to certificate / private key will be
// converted to absolute form internally. If any error happened during the first
// reload, New will return a nil Reloader and non-nil error.
func New(certPath, keyPath string, interval time.Duration) (*Reloader, error) {
	var err error
	if certPath, err = filepath.Abs(certPath); err != nil {
		return nil, err
	}
	if keyPath, err = filepath.Abs(keyPath); err != nil {
		return nil, err
	}
	r := &Reloader{
		certPath: certPath,
		keyPath:  keyPath,
	}
	if err = r.reload(); err != nil {
		return nil, err
	}
	ticker := time.NewTicker(interval)
	chStop := make(chan struct{})
	go func() {
		<-chStop
		ticker.Stop()
	}()
	r.chStop = chStop
	go func(ch <-chan time.Time) {
		for {
			<-ch
			if err := r.reload(); err != nil {
				log.Print(err) // TODO: first error only?
			}
		}
	}(ticker.C)
	return r, nil
}

// Stop further reloading. A stopped reloader cannot be started again. Loaded
// certificate is still available. Call this method if you don't want resource
// leak.
func (r *Reloader) Stop() {
	select {
	case <-r.chStop:
	default:
		close(r.chStop)
	}
}

func (r *Reloader) reload() error {
	var (
		err     error
		certPEM []byte
		keyPEM  []byte
		cert    tls.Certificate
	)
	if certPEM, err = ioutil.ReadFile(r.certPath); err != nil {
		return fmt.Errorf("unable to read certificate: %v", err)
	}
	if keyPEM, err = ioutil.ReadFile(r.keyPath); err != nil {
		return fmt.Errorf("unable to read private key: %v", err)
	}
	if bytes.Equal(certPEM, r.certPEM) && bytes.Equal(keyPEM, r.keyPEM) {
		return nil
	}
	if cert, err = tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return err
	}
	r.certPEM = certPEM
	r.keyPEM = keyPEM
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&r.cert)), unsafe.Pointer(&cert))
	return nil
}

// Get currently loaded tls.Certificate.
func (r *Reloader) Get() *tls.Certificate {
	return (*tls.Certificate)(atomic.LoadPointer(
		(*unsafe.Pointer)(unsafe.Pointer(&r.cert))))
}
