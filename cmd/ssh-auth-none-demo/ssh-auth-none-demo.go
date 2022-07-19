package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	gossh "github.com/tailscale/golang-x-crypto/ssh"
	"tailscale.com/tempfork/gliderlabs/ssh"
)

// keyTypes are the SSH key types that we either try to read from the
// system's OpenSSH keys.
var keyTypes = []string{"rsa", "ecdsa", "ed25519"}

func main() {
	srv := &ssh.Server{
		Addr:    ":2222",
		Version: "Tailscale",
		Handler: handleSessionPostSSHAuth,
		ServerConfigCallback: func(ctx ssh.Context) *gossh.ServerConfig {
			return &gossh.ServerConfig{
				ImplictAuthMethod: "tailscale",
				NoClientAuth:      true, // required for the NoClientAuthCallback to run
				NoClientAuthCallback: func(gossh.ConnMetadata) (*gossh.Permissions, error) {
					return nil, nil
				},
			}
		},
	}

	keys, err := getSystemSSH_HostKeys()
	if err != nil {
		log.Fatal(err)
	}
	if len(keys) == 0 {
		log.Fatal("no host keys")
	}
	for _, signer := range keys {
		srv.AddHostKey(signer)
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
	log.Printf("done")
}

func handleSessionPostSSHAuth(s ssh.Session) {
	fmt.Fprintf(s, "It worked.\n")
	for i := 10; i > 0; i-- {
		fmt.Fprintf(s, "%v ...\n", i)
		time.Sleep(time.Second)
	}
	s.Exit(0)
}

func getSystemSSH_HostKeys() (ret []ssh.Signer, err error) {
	for _, typ := range keyTypes {
		hostKey, err := ioutil.ReadFile("/etc/ssh/ssh_host_" + typ + "_key")
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		signer, err := gossh.ParsePrivateKey(hostKey)
		if err != nil {
			return nil, err
		}
		ret = append(ret, signer)
	}
	return ret, nil
}
