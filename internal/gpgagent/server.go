package gpgagent

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type Server struct {
	socketPath string
	listener   net.Listener
	keyStore   *KeyStore
	running    bool
}

func NewServer(socketPath string) *Server {
	return &Server{
		socketPath: socketPath,
		keyStore:   NewKeyStore(),
	}
}

func (s *Server) AddKey(armoredKey string) error {
	return s.keyStore.AddKey(armoredKey)
}

func (s *Server) SocketPath() string {
	return s.socketPath
}

func (s *Server) Start() error {
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	if err := os.Chmod(s.socketPath, 0600); err != nil {
		listener.Close()

		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	s.listener = listener
	s.running = true

	return nil
}

func (s *Server) Serve() error {
	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if !s.running {
				return nil
			}

			continue
		}

		go s.handleConnection(conn)
	}

	return nil
}

func (s *Server) Stop() error {
	s.running = false

	if s.listener != nil {
		s.listener.Close()
	}

	os.Remove(s.socketPath)

	return nil
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	ac := NewAssuanConn(conn, conn)

	if err := ac.WriteOK("gopass gpg-agent ready"); err != nil {
		return
	}

	session := &agentSession{
		server: s,
		conn:   ac,
	}

	for {
		line, err := ac.ReadLine()
		if err != nil {
			if err != io.EOF {
				ac.WriteError(1, "read error")
			}

			return
		}

		cmd, args := ParseCommand(line)

		if err := session.handleCommand(cmd, args); err != nil {
			if err == errQuit {
				return
			}

			ac.WriteError(1, err.Error())
		}
	}
}

var errQuit = fmt.Errorf("quit")

type agentSession struct {
	server     *Server
	conn       *AssuanConn
	signingKey string
	hashAlgo   crypto.Hash
}

func (s *agentSession) handleCommand(cmd, args string) error {
	switch cmd {
	case "NOP":
		return s.conn.WriteOK("")

	case "GETINFO":
		return s.handleGetInfo(args)

	case "AGENT_ID":
		return s.conn.WriteOK("gopass-agent")

	case "KEYINFO":
		return s.handleKeyInfo(args)

	case "HAVEKEY":
		return s.handleHaveKey(args)

	case "SIGKEY", "SETKEY":
		return s.handleSigKey(args)

	case "SETHASH":
		return s.handleSetHash(args)

	case "PKSIGN":
		return s.handlePKSign(args)

	case "PKDECRYPT":
		return s.handlePKDecrypt(args)

	case "RESET":
		s.signingKey = ""
		s.hashAlgo = 0

		return s.conn.WriteOK("")

	case "OPTION":
		return s.conn.WriteOK("")

	case "BYE":
		s.conn.WriteOK("closing connection")

		return errQuit

	case "KILLAGENT":
		s.conn.WriteOK("agent will terminate")
		s.server.Stop()

		return errQuit

	default:
		return s.conn.WriteError(536871187, fmt.Sprintf("unknown command: %s", cmd))
	}
}

func (s *agentSession) handleGetInfo(args string) error {
	switch args {
	case "version":
		return s.conn.WriteOK("1.0.0")

	case "pid":
		return s.conn.WriteOK(fmt.Sprintf("%d", os.Getpid()))

	case "socket_name":
		s.conn.WriteData([]byte(s.server.socketPath))

		return s.conn.WriteOK("")

	case "cmd_has_option":
		return s.conn.WriteOK("")

	default:
		return s.conn.WriteError(536871187, "unknown info request")
	}
}

func (s *agentSession) handleKeyInfo(_ string) error {
	keygrips := s.server.keyStore.ListKeygrips()

	for _, keygrip := range keygrips {
		info := fmt.Sprintf("%s D - - - - - - -", keygrip)
		s.conn.WriteStatus("KEYINFO", info)
	}

	return s.conn.WriteOK("")
}

func (s *agentSession) handleHaveKey(args string) error {
	keygrips := strings.Fields(args)

	for _, keygrip := range keygrips {
		if s.server.keyStore.HasKey(keygrip) {
			return s.conn.WriteOK("")
		}
	}

	return s.conn.WriteError(67108881, "no secret key")
}

func (s *agentSession) handleSigKey(args string) error {
	s.signingKey = strings.TrimSpace(args)

	return s.conn.WriteOK("")
}

func (s *agentSession) handleSetHash(args string) error {
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return s.conn.WriteError(536871187, "invalid arguments")
	}

	algoStr := parts[0]

	switch algoStr {
	case "2":
		s.hashAlgo = crypto.SHA1
	case "8":
		s.hashAlgo = crypto.SHA256
	case "9":
		s.hashAlgo = crypto.SHA384
	case "10":
		s.hashAlgo = crypto.SHA512
	default:
		s.hashAlgo = crypto.SHA256
	}

	return s.conn.WriteOK("")
}

func (s *agentSession) handlePKSign(_ string) error {
	if s.signingKey == "" {
		return s.conn.WriteError(536871187, "no signing key set")
	}

	signer, err := s.server.keyStore.GetSigner(s.signingKey)
	if err != nil {
		return s.conn.WriteError(67108881, err.Error())
	}

	hashData := make([]byte, 32)
	rand.Read(hashData)

	signature, err := signer.Sign(rand.Reader, hashData, s.hashAlgo)
	if err != nil {
		return s.conn.WriteError(536871187, err.Error())
	}

	s.conn.WriteData(signature)

	return s.conn.WriteOK("")
}

func (s *agentSession) handlePKDecrypt(_ string) error {
	s.conn.WriteInquire("CIPHERTEXT")

	line, err := s.conn.ReadLine()
	if err != nil {
		return err
	}

	if !strings.HasPrefix(line, "D ") {
		return s.conn.WriteError(536871187, "expected ciphertext data")
	}

	ciphertext, err := hex.DecodeString(strings.TrimPrefix(line, "D "))
	if err != nil {
		return s.conn.WriteError(536871187, "invalid ciphertext encoding")
	}

	_, err = s.conn.ReadLine()
	if err != nil {
		return err
	}

	keygrips := s.server.keyStore.ListKeygrips()
	if len(keygrips) == 0 {
		return s.conn.WriteError(67108881, "no decryption key available")
	}

	decrypter, err := s.server.keyStore.GetDecrypter(keygrips[0])
	if err != nil {
		return s.conn.WriteError(67108881, err.Error())
	}

	plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
	if err != nil {
		return s.conn.WriteError(536871187, err.Error())
	}

	s.conn.WriteData(plaintext)

	return s.conn.WriteOK("")
}
