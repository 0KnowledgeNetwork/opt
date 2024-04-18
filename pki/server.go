package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"

	"github.com/0knowledgenetwork/opt/config"
)

// ErrGenerateOnly is the error returned when the server initialization
// terminates due to the `GenerateOnly` debug config option.
var ErrGenerateOnly = errors.New("server: GenerateOnly set")

type Server struct {
	cfg *config.Config
	geo *geo.Geometry

	identityPrivateKey sign.PrivateKey
	identityPublicKey  sign.PublicKey
	linkKey            kem.PrivateKey

	logBackend *log.Backend
	log        *logging.Logger

	listeners []net.Listener

	wg         *sync.WaitGroup
	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once
}

func (s *Server) initDataDir() error {
	const dirMode = os.ModeDir | 0700
	d := s.cfg.Server.DataDir

	// Initialize the data directory, by ensuring that it exists (or can be
	// created), and that it has the appropriate permissions.
	if fi, err := os.Lstat(d); err != nil {
		// Directory doesn't exist, create one.
		if !os.IsNotExist(err) {
			return fmt.Errorf("authority: failed to stat() DataDir: %v", err)
		}
		if err = os.Mkdir(d, dirMode); err != nil {
			return fmt.Errorf("authority: failed to create DataDir: %v", err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("authority: DataDir '%v' is not a directory", d)
		}
		if fi.Mode() != dirMode {
			return fmt.Errorf("authority: DataDir '%v' has invalid permissions '%v'", d, fi.Mode())
		}
	}

	return nil
}

func (s *Server) initLogging() error {
	p := s.cfg.Logging.File
	if !s.cfg.Logging.Disable && s.cfg.Logging.File != "" {
		if !filepath.IsAbs(p) {
			p = filepath.Join(s.cfg.Server.DataDir, p)
		}
	}

	var err error
	s.logBackend, err = log.New(p, s.cfg.Logging.Level, s.cfg.Logging.Disable)
	if err == nil {
		s.log = s.logBackend.GetLogger("authority")
	}
	return err
}

// Wait waits till the server is terminated for any reason.
func (s *Server) Wait() {
	<-s.haltedCh
}

// Shutdown cleanly shuts down a given Server instance.
func (s *Server) Shutdown() {
	s.haltOnce.Do(func() { s.halt() })
}

func (s *Server) listenWorker(l net.Listener) {
	addr := l.Addr()
	s.log.Noticef("Listening on: %v", addr)
	defer func() {
		s.log.Noticef("Stopping listening on: %v", addr)
		l.Close()
		s.wg.Done()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				s.log.Errorf("Critical accept failure: %v", err)
				return
			}
			continue
		}

		s.wg.Add(1)

		// FIXME(david): handle connections, remove stupid print statement.
		//s.onConn(conn)
		fmt.Println("conn %v", conn)
	}

	// NOTREACHED
}

func (s *Server) halt() {
	s.log.Notice("Starting graceful shutdown.")

	// Halt the listeners.
	for idx, l := range s.listeners {
		if l != nil {
			l.Close()
		}
		s.listeners[idx] = nil
	}

	// Wait for all the connections to terminate.
	s.wg.Wait()
	close(s.fatalErrCh)
	s.log.Notice("Shutdown complete.")
	close(s.haltedCh)
}

func New(cfg *config.Config) (*Server, error) {
	s := new(Server)
	s.cfg = cfg
	s.geo = cfg.SphinxGeometry
	s.fatalErrCh = make(chan error)
	s.haltedCh = make(chan interface{})
	s.wg = new(sync.WaitGroup)

	// Do the early initialization and bring up logging.
	if err := s.initDataDir(); err != nil {
		return nil, err
	}
	if err := s.initLogging(); err != nil {
		return nil, err
	}

	s.log.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")
	if s.cfg.Logging.Level == "DEBUG" {
		s.log.Warning("Unsafe Debug logging is enabled.")
	}

	// Initialize the authority identity key.
	identityPrivateKeyFile := filepath.Join(s.cfg.Server.DataDir, "identity.private.pem")
	identityPublicKeyFile := filepath.Join(s.cfg.Server.DataDir, "identity.public.pem")

	var err error

	if utils.BothExists(identityPrivateKeyFile, identityPublicKeyFile) {
		s.identityPrivateKey, err = signpem.FromPrivatePEMFile(identityPrivateKeyFile, cert.Scheme)
		if err != nil {
			return nil, err
		}
		s.identityPublicKey, err = signpem.FromPublicPEMFile(identityPublicKeyFile, cert.Scheme)
		if err != nil {
			return nil, err
		}
	} else if utils.BothNotExists(identityPrivateKeyFile, identityPublicKeyFile) {
		s.identityPublicKey, s.identityPrivateKey, err = cert.Scheme.GenerateKey()
		if err != nil {
			return nil, err
		}
		err = signpem.PrivateKeyToFile(identityPrivateKeyFile, s.identityPrivateKey)
		if err != nil {
			return nil, err
		}
		err = signpem.PublicKeyToFile(identityPublicKeyFile, s.identityPublicKey)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("%s and %s must either both exist or not exist", identityPrivateKeyFile, identityPublicKeyFile)
	}

	scheme := schemes.ByName(cfg.Server.WireKEMScheme)
	if scheme == nil {
		return nil, errors.New("KEM scheme not found in registry")
	}
	linkPrivateKeyFile := filepath.Join(s.cfg.Server.DataDir, "link.private.pem")
	linkPublicKeyFile := filepath.Join(s.cfg.Server.DataDir, "link.public.pem")

	var linkPrivateKey kem.PrivateKey

	if utils.BothExists(linkPrivateKeyFile, linkPublicKeyFile) {
		linkPrivateKey, err = kempem.FromPrivatePEMFile(linkPrivateKeyFile, scheme)
		if err != nil {
			return nil, err
		}
		_, err = kempem.FromPublicPEMFile(linkPublicKeyFile, scheme)
		if err != nil {
			return nil, err
		}
	} else if utils.BothNotExists(linkPrivateKeyFile, linkPublicKeyFile) {
		linkPublicKey, linkPrivateKey, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}

		err = kempem.PrivateKeyToFile(linkPrivateKeyFile, linkPrivateKey)
		if err != nil {
			return nil, err
		}
		err = kempem.PublicKeyToFile(linkPublicKeyFile, linkPublicKey)
		if err != nil {
			return nil, err
		}
	} else {
		panic("Improbable: Only found one link PEM file.")
	}

	s.linkKey = linkPrivateKey

	s.log.Noticef("Authority identity public key hash is: %x", hash.Sum256From(s.identityPublicKey))
	linkBlob, err := s.linkKey.Public().MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.log.Noticef("Authority link public key hash is: %x", sha256.Sum256(linkBlob))

	if s.cfg.Debug.GenerateOnly {
		return nil, ErrGenerateOnly
	}

	// Past this point, failures need to call s.Shutdown() to do cleanup.
	isOk := false
	defer func() {
		if !isOk {
			s.Shutdown()
		}
	}()

	// Start the fatal error watcher.
	go func() {
		err, ok := <-s.fatalErrCh
		if !ok {
			return
		}
		s.log.Warningf("Shutting down due to error: %v", err)
		s.Shutdown()
	}()

	// Start up the listeners.
	for _, v := range s.cfg.Server.Addresses {
		l, err := net.Listen("tcp", v)
		if err != nil {
			s.log.Errorf("Failed to start listener '%v': %v", v, err)
			continue
		}
		s.listeners = append(s.listeners, l)
		s.wg.Add(1)
		go s.listenWorker(l)
	}
	if len(s.listeners) == 0 {
		s.log.Errorf("Failed to start all listeners.")
		return nil, fmt.Errorf("authority: failed to start all listeners")
	}

	isOk = true
	return s, nil
}
