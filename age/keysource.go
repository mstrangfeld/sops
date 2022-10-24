package age

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"github.com/sirupsen/logrus"
	"go.mozilla.org/sops/v3/logging"
	"golang.org/x/crypto/ssh"
)

var log *logrus.Logger

func init() {
	log = logging.NewLogger("AGE")
}

const SopsAgeKeyEnv = "SOPS_AGE_KEY"
const SopsAgeKeyFileEnv = "SOPS_AGE_KEY_FILE"
const SopsAgeSshPrivateKeyEnv = "SOPS_AGE_SSH_PRIVATE_KEY"

// MasterKey is an age key used to encrypt and decrypt sops' data key.
type MasterKey struct {
	Identity     string // a Bech32-encoded private key
	Recipient    string // a Bech32-encoded public key
	EncryptedKey string // a sops data key encrypted with age

	parsedRecipient age.Recipient // a parsed age public key
}

// Encrypt takes a sops data key, encrypts it with age and stores the result in the EncryptedKey field.
func (key *MasterKey) Encrypt(datakey []byte) error {
	buffer := &bytes.Buffer{}

	if key.parsedRecipient == nil {
		parsedRecipient, err := parseRecipient(key.Recipient)

		if err != nil {
			log.WithField("recipient", key.parsedRecipient).Error("Encryption failed")
			return err
		}

		key.parsedRecipient = parsedRecipient
	}

	aw := armor.NewWriter(buffer)
	w, err := age.Encrypt(aw, key.parsedRecipient)
	if err != nil {
		return fmt.Errorf("failed to open file for encrypting sops data key with age: %w", err)
	}

	if _, err := w.Write(datakey); err != nil {
		log.WithField("recipient", key.parsedRecipient).Error("Encryption failed")
		return fmt.Errorf("failed to encrypt sops data key with age: %w", err)
	}

	if err := w.Close(); err != nil {
		log.WithField("recipient", key.parsedRecipient).Error("Encryption failed")
		return fmt.Errorf("failed to close file for encrypting sops data key with age: %w", err)
	}

	if err := aw.Close(); err != nil {
		log.WithField("recipient", key.parsedRecipient).Error("Encryption failed")
		return fmt.Errorf("failed to close armored writer: %w", err)
	}

	key.EncryptedKey = buffer.String()

	log.WithField("recipient", key.parsedRecipient).Info("Encryption succeeded")

	return nil
}

// EncryptIfNeeded encrypts the provided sops' data key and encrypts it if it hasn't been encrypted yet.
func (key *MasterKey) EncryptIfNeeded(datakey []byte) error {
	if key.EncryptedKey == "" {
		return key.Encrypt(datakey)
	}

	return nil
}

// EncryptedDataKey returns the encrypted data key this master key holds.
func (key *MasterKey) EncryptedDataKey() []byte {
	return []byte(key.EncryptedKey)
}

// SetEncryptedDataKey sets the encrypted data key for this master key.
func (key *MasterKey) SetEncryptedDataKey(enc []byte) {
	key.EncryptedKey = string(enc)
}

func getAgeIdentities() ([]age.Identity, error) {
	var ageKeyReader io.Reader

	if ageKeyReader == nil {
		ageKey, ok := os.LookupEnv(SopsAgeKeyEnv)
		if ok {
			ageKeyReader = strings.NewReader(ageKey)
		}
	}

	if ageKeyReader == nil {
		ageKeyFilePath, ok := os.LookupEnv(SopsAgeKeyFileEnv)
		if ok {
			ageKeyFile, err := os.Open(ageKeyFilePath)
			if err != nil {
				return nil, fmt.Errorf("failed to open file: %w", err)
			}
			defer ageKeyFile.Close()
			ageKeyReader = ageKeyFile
		}
	}

	if ageKeyReader == nil {
		userConfigDir, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("user config directory could not be determined: %w", err)
		}
		ageKeyFilePath := filepath.Join(userConfigDir, "sops", "age", "keys.txt")
		if _, err := os.Stat(ageKeyFilePath); errors.Is(err, os.ErrNotExist) {
			// Exit silently when the file does not exist
			return nil, nil
		}
		ageKeyFile, err := os.Open(ageKeyFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}
		defer ageKeyFile.Close()
		ageKeyReader = ageKeyFile
	}

	if ageKeyReader == nil {
		return nil, nil
	}

	return age.ParseIdentities(ageKeyReader)
}

func readPublicKeyFile(privateKeyPath string) (ssh.PublicKey, error) {
	publicKeyPath := privateKeyPath + ".pub"
	f, err := os.Open(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain public %q key for %q SSH key: %w", publicKeyPath, privateKeyPath, err)
	}
	defer f.Close()
	contents, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", publicKeyPath, err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(contents)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %w", publicKeyPath, err)
	}
	return pubKey, nil
}

func getAgeSshIdentityFromPrivateKeyFile(keyPath string) (age.Identity, error) {
	keyFile, err := os.Open(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer keyFile.Close()
	contents, err := ioutil.ReadAll(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	id, err := agessh.ParseIdentity(contents)
	if sshErr, ok := err.(*ssh.PassphraseMissingError); ok {
		pubKey := sshErr.PublicKey
		if pubKey == nil {
			pubKey, err = readPublicKeyFile(keyPath)
			if err != nil {
				return nil, err
			}
		}
		passphrasePrompt := func() ([]byte, error) {
			pass, err := readPassphrase(fmt.Sprintf("Enter passphrase for %q:", keyPath))
			if err != nil {
				return nil, fmt.Errorf("could not read passphrase for %q: %v", keyPath, err)
			}
			return pass, nil
		}
		i, err := agessh.NewEncryptedSSHIdentity(pubKey, contents, passphrasePrompt)
		if err != nil {
			return nil, fmt.Errorf("could not create encrypted SSH identity: %w", err)
		}
		return i, nil
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH identity in %q: %w", keyPath, err)
	}
	return id, nil
}

func getAgeSshIdentity() (age.Identity, error) {
	sshKeyFilePath, ok := os.LookupEnv(SopsAgeSshPrivateKeyEnv)
	if ok {
		return getAgeSshIdentityFromPrivateKeyFile(sshKeyFilePath)
	}

	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("user home directory could not be determined: %w", err)
	}

	sshEd25519PrivateKeyPath := filepath.Join(userHomeDir, ".ssh", "id_ed25519")
	if _, err := os.Stat(sshEd25519PrivateKeyPath); err == nil {
		return getAgeSshIdentityFromPrivateKeyFile(sshEd25519PrivateKeyPath)
	}

	sshRsaPrivateKeyPath := filepath.Join(userHomeDir, ".ssh", "id_rsa")
	if _, err := os.Stat(sshEd25519PrivateKeyPath); err == nil {
		return getAgeSshIdentityFromPrivateKeyFile(sshRsaPrivateKeyPath)
	}

	return nil, nil
}

// Decrypt decrypts the EncryptedKey field with the age identity and returns the result.
func (key *MasterKey) Decrypt() ([]byte, error) {
	var identities []age.Identity

	ageIdentities, err := getAgeIdentities()
	if err != nil {
		return nil, fmt.Errorf("failed to read age identities: %w", err)
	}
	identities = append(identities, ageIdentities...)

	ageSshIdentity, err := getAgeSshIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to read age ssh identities: %w", err)
	}
	identities = append(identities, ageSshIdentity)

	if len(identities) < 1 {
		return nil, fmt.Errorf("no age identity found")
	}

	src := bytes.NewReader([]byte(key.EncryptedKey))
	ar := armor.NewReader(src)
	r, err := age.Decrypt(ar, identities...)

	if err != nil {
		return nil, fmt.Errorf("no age identity found that could decrypt the data")
	}

	var b bytes.Buffer
	if _, err := io.Copy(&b, r); err != nil {
		return nil, fmt.Errorf("failed to copy decrypted data into bytes.Buffer: %w", err)
	}

	return b.Bytes(), nil
}

// NeedsRotation returns whether the data key needs to be rotated or not.
func (key *MasterKey) NeedsRotation() bool {
	return false
}

// ToString converts the key to a string representation.
func (key *MasterKey) ToString() string {
	return key.Recipient
}

// ToMap converts the MasterKey to a map for seriazation purposes.
func (key *MasterKey) ToMap() map[string]interface{} {
	return map[string]interface{}{"recipient": key.Recipient, "enc": key.EncryptedKey}
}

// MasterKeysFromRecipients takes a comma-separated list of Bech32-encoded public keys and returns a
// slice of new MasterKeys.
func MasterKeysFromRecipients(commaSeparatedRecipients string) ([]*MasterKey, error) {
	if commaSeparatedRecipients == "" {
		// otherwise Split returns [""] and MasterKeyFromRecipient is unhappy
		return make([]*MasterKey, 0), nil
	}
	recipients := strings.Split(commaSeparatedRecipients, ",")

	var keys []*MasterKey

	for _, recipient := range recipients {
		key, err := masterKeyFromRecipient(recipient)

		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// masterKeyFromRecipient takes a Bech32-encoded public key and returns a new MasterKey.
func masterKeyFromRecipient(recipient string) (*MasterKey, error) {
	recipient = strings.TrimSpace(recipient)
	parsedRecipient, err := parseRecipient(recipient)

	if err != nil {
		return nil, err
	}

	return &MasterKey{
		Recipient:       recipient,
		parsedRecipient: parsedRecipient,
	}, nil
}

// parseRecipient attempts to parse a string containing an encoded age public key
func parseRecipient(recipient string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(recipient, "age1"):
		parsedRecipient, err := age.ParseX25519Recipient(recipient)
		if err != nil {
			return nil, fmt.Errorf("failed to parse input as Bech32-encoded age public key: %w", err)
		}

		return parsedRecipient, nil
	case strings.HasPrefix(recipient, "ssh-"):
		parsedRecipient, err := agessh.ParseRecipient(recipient)
		if err != nil {
			return nil, fmt.Errorf("failed to parse input as age-ssh public key: %w", err)
		}
		return parsedRecipient, nil
	}

	return nil, fmt.Errorf("failed to parse input, unknown recipient type: %q", recipient)
}
