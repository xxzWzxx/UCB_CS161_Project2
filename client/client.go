package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

const sigLength = 256
const macLength = 64

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
	sourceKey     []byte
	structEncKey  []byte
	structMacKey  []byte
	Username      string
	EncKeys       map[string][]byte
	MacKeys       map[string][]byte
	SignKey       userlib.DSSignKey
	PrivateDecKey userlib.PKEDecKey
}

type Identity struct {
	IdentityKey []byte
	Salt        []byte
}

func generateSymKey(sourceKey []byte, purpose string, keySize int) (newKey []byte, err error) {
	newKey, err = userlib.HashKDF(sourceKey, []byte(purpose))
	if err != nil {
		err = errors.New("An error occurred while generating a new symmetric key: " + err.Error())
		return nil, err
	}
	return newKey[:keySize], nil
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var (
		userdata     User
		userIdentity Identity
		VerifyKey    userlib.DSVerifyKey
		PublicEncKey userlib.PKEEncKey
	)

	// Initialize the user structure
	userdata.Username = username
	salt := userlib.RandomBytes(userlib.AESKeySizeBytes)
	userdata.sourceKey = userlib.Argon2Key([]byte(password), salt, userlib.AESKeySizeBytes)
	userdata.structEncKey, err = generateSymKey(userdata.sourceKey, "structEncKey", userlib.AESKeySizeBytes)
	if err != nil {
		return nil, err
	}
	userdata.structMacKey, err = generateSymKey(userdata.sourceKey, "structMacKey", userlib.AESKeySizeBytes)
	if err != nil {
		return nil, err
	}
	userdata.SignKey, VerifyKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	PublicEncKey, userdata.PrivateDecKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.EncKeys = make(map[string][]byte)
	userdata.MacKeys = make(map[string][]byte)

	// Create identity structure
	userIdentity.IdentityKey, err = userlib.HashKDF(userdata.sourceKey, []byte("identityKey"))
	if err != nil {
		return nil, err
	}
	userIdentity.Salt = salt

	// Generate UUIDs
	userUUID, err := getUserUUID(username)
	identityUUID, err := getIdentityUUID(username)

	// Store the public encryption key and sign key
	err = userlib.KeystoreSet(getEncKeyName(username), PublicEncKey)
	if err != nil {
		err = errors.New("An error occurred when store public encryption key to KeyStore" + err.Error())
		return nil, err
	}
	err = userlib.KeystoreSet(getVerifyKeyName(username), VerifyKey)
	if err != nil {
		err = errors.New("An error occurred when store verify key to Key Store" + err.Error())
		return nil, err
	}

	// Sign and store the user identity
	userIdentityBytes, err := json.Marshal(userIdentity)
	if err != nil {
		return nil, err
	}
	signature, err := userlib.DSSign(userdata.SignKey, userlib.Hash(userIdentityBytes))
	if err != nil {
		return nil, err
	}
	sig_value_pair := append(signature, userIdentityBytes...)
	userlib.DatastoreSet(identityUUID, sig_value_pair)

	// Encrypt, MAC and store the user structure
	userStructBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	iv := userlib.RandomBytes(userlib.AESKeySizeBytes)
	cipherStruct := userlib.SymEnc(userdata.structEncKey, iv, userStructBytes)
	mac, err := userlib.HMACEval(userdata.structMacKey, cipherStruct)
	if err != nil {
		return nil, err
	}
	mac_value_pair := append(mac, cipherStruct...)
	userlib.DatastoreSet(userUUID, mac_value_pair)

	return &userdata, nil
}

func getEncKeyName(username string) string {
	result := fmt.Sprintf("EncKey/%s", username)
	return result
}

func getVerifyKeyName(username string) string {
	result := fmt.Sprintf("VerifyKey/%s", username)
	return result
}

func getUserUUID(username string) (userUUID userlib.UUID, err error) {
	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-struct/" + username))
	userUUID, err = uuid.FromBytes(hash[:16])
	if err != nil {
		err = errors.New("An error occurred while generating user structure UUID: " + err.Error())
	}
	return userUUID, err
}

func getIdentityUUID(username string) (userUUID userlib.UUID, err error) {
	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-identity/" + username))
	userUUID, err = uuid.FromBytes(hash[:16])
	if err != nil {
		err = errors.New("An error occurred while generating user identity UUID: " + err.Error())
	}
	return userUUID, err
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Generate UUIDs for user's identity and structure
	userUUID, err := getUserUUID(username)
	if err != nil {
		return nil, err
	}
	identityUUID, err := getIdentityUUID(username)
	if err != nil {
		return nil, err
	}

	// Get user identity from Datastore and verify it
	sig_identity, err := loadDatastore(identityUUID)
	if err != nil {
		return nil, err
	}
	verificationKey, ok := userlib.KeystoreGet(getVerifyKeyName(username))
	if !ok {
		err = errors.New("An error occurred while downloading data from Datastore: cannot find user's verification key.")
		return nil, err
	}
	sig := sig_identity[:sigLength]
	userIdentityBytes := sig_identity[sigLength:]
	err = userlib.DSVerify(verificationKey, userlib.Hash(userIdentityBytes), sig)
	if err != nil {
		return nil, err
	}
	var userIdentity Identity
	err = json.Unmarshal(userIdentityBytes, &userIdentity)
	if err != nil {
		return nil, err
	}

	// Generate sourceKey, identity key, structure encryption key and structure mac key
	sourceKey := userlib.Argon2Key([]byte(password), userIdentity.Salt, userlib.AESKeySizeBytes)
	identityNew, err := userlib.HashKDF(sourceKey, []byte("identityKey"))
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(identityNew, userIdentity.IdentityKey) {
		err = errors.New("An error occurred while verifying user identity: password incorrect.")
		return nil, err
	}
	structEncKey, err := generateSymKey(sourceKey, "structEncKey", userlib.AESKeySizeBytes)
	if err != nil {
		return nil, err
	}
	structMacKey, err := generateSymKey(sourceKey, "structMacKey", userlib.AESKeySizeBytes)
	if err != nil {
		return nil, err
	}

	// Authenticate then decrypt the stored user structure
	mac_userStruct, err := loadDatastore(userUUID)
	if err != nil {
		return nil, err
	}
	mac := mac_userStruct[:macLength]
	cipherStruct := mac_userStruct[macLength:]
	macNew, err := userlib.HMACEval(structMacKey, cipherStruct)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(macNew, mac) {
		err = errors.New("An error occurred while checking the MAC value: the content is tampered.")
		return nil, err
	}
	userStructBytes := userlib.SymDec(structEncKey, cipherStruct)
	err = json.Unmarshal(userStructBytes, userdataptr)
	if err != nil {
		return nil, err
	}
	userdataptr.sourceKey = sourceKey
	userdataptr.structEncKey = structEncKey
	userdataptr.structMacKey = structMacKey
	return userdataptr, nil
}

func loadDatastore(key userlib.UUID) (value []byte, err error) {
	value, ok := userlib.DatastoreGet(key)
	if !ok {
		err = errors.New("An error occurred while downloading data from Datastore: cannot find data correspoinding to UUID provided.")
		return nil, err
	}
	return value, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
