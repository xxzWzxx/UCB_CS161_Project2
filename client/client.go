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

func InitUser(username string, password string) (userdataptr *User, err error) {
	var (
		userdata     User
		userIdentity Identity
		VerifyKey    userlib.DSVerifyKey
		PublicEncKey userlib.PKEEncKey
	)
	// Return error when empty username is provided
	if len(username) == 0 {
		err = errors.New("An error occurred when creating user: Empty username is provided.")
		return nil, err
	}

	// Generate UUIDs
	userUUID, err := GetUserUUID(username)
	if err != nil {
		return nil, err
	}
	identityUUID, err := GetIdentityUUID(username)
	if err != nil {
		return nil, err
	}

	// Generate keys to store sign key and verify key
	encKeyName := getPEKeyName(username)
	verifyKeyName := getVerifyKeyName(username)

	// If the user already exists, return an error
	_, ok := userlib.KeystoreGet(encKeyName)
	if ok {
		err = errors.New("An error occurred when creating user: The username already exists.")
		return nil, err
	}

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

	// Store the public encryption key and sign key
	err = userlib.KeystoreSet(encKeyName, PublicEncKey)
	if err != nil {
		err = errors.New("An error occurred when store public encryption key to KeyStore" + err.Error())
		return nil, err
	}
	err = userlib.KeystoreSet(verifyKeyName, VerifyKey)
	if err != nil {
		err = errors.New("An error occurred when store verify key to Key Store" + err.Error())
		return nil, err
	}

	// Sign and store the user identity
	userIdentityBytes, err := json.Marshal(userIdentity)
	if err != nil {
		return nil, err
	}
	sig_value_pair, err := getSignedMsg(userIdentityBytes, userdata.SignKey)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(identityUUID, sig_value_pair)

	// Encrypt, MAC and store the user structure
	userStructBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	mac_value_pair, err := encThenMac(userStructBytes, userdata.structEncKey, userdata.structMacKey)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(userUUID, mac_value_pair)

	return &userdata, nil
}

func encThenMac(msg []byte, encKey []byte, macKey []byte) (macCipherMsg []byte, err error) {
	// Encrypt the `msg` with `encKey` in symmetric encryption scheme and use the `macKey` to authenticate it
	// Return the cihper text along with MAC in the for MAC||CipherText
	iv := userlib.RandomBytes(userlib.AESKeySizeBytes)
	cipherMsg := userlib.SymEnc(encKey, iv, msg)
	mac, err := userlib.HMACEval(macKey, cipherMsg)
	if err != nil {
		return nil, err
	}
	macCipherMsg = append(mac, cipherMsg...)
	return macCipherMsg, nil
}

func getSignedMsg(msg []byte, signKey userlib.PrivateKeyType) (sigMsg []byte, err error) {
	signature, err := userlib.DSSign(signKey, userlib.Hash(msg))
	if err != nil {
		return nil, err
	}
	sig_value_pair := append(signature, msg...)
	return sig_value_pair, nil
}

func getPEKeyName(username string) string {
	// Get the key for storing public encryption key pair
	result := fmt.Sprintf("EncKey/%s", username)
	return result
}

func getVerifyKeyName(username string) string {
	result := fmt.Sprintf("VerifyKey/%s", username)
	return result
}

func GetUserUUID(username string) (userUUID userlib.UUID, err error) {
	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-struct/" + username))
	userUUID, err = uuid.FromBytes(hash[:16])
	if err != nil {
		err = errors.New("An error occurred while generating user structure UUID: " + err.Error())
	}
	return userUUID, err
}

func GetIdentityUUID(username string) (userUUID userlib.UUID, err error) {
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
	userUUID, err := GetUserUUID(username)
	if err != nil {
		return nil, err
	}
	identityUUID, err := GetIdentityUUID(username)
	if err != nil {
		return nil, err
	}

	// Get user identity from Datastore and verify it
	verificationKey, ok := userlib.KeystoreGet(getVerifyKeyName(username))
	if !ok {
		err = errors.New("An error occurred while login: The user is not initialized.")
		return nil, err
	}
	sig_identity, err := loadDatastore(identityUUID)
	if err != nil {
		return nil, err
	}
	err = VerifySig(sig_identity, verificationKey)
	if err != nil {
		return nil, err
	}
	userIdentityBytes := sig_identity[sigLength:]
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
		err = errors.New("An error occurred while login: password incorrect.")
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
	err = AuthenticateMac(mac_userStruct, structMacKey)
	if err != nil {
		return nil, err
	}
	cipherStruct := mac_userStruct[macLength:]
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

func AuthenticateMac(mac_data []byte, macKey []byte) (err error) {
	mac := mac_data[:macLength]
	data := mac_data[macLength:]
	macNew, err := userlib.HMACEval(macKey, data)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(macNew, mac) {
		err = errors.New("An error occurred while authenticating the data: the data is tampered.")
		return err
	}
	return nil
}

func VerifySig(sig_data []byte, verifyKey userlib.DSVerifyKey) (err error) {
	// Verify data with signature in the form signature||data
	sig := sig_data[:sigLength]
	data := sig_data[sigLength:]
	err = userlib.DSVerify(verifyKey, userlib.Hash(data), sig)
	if err != nil {
		err = errors.New("An error occurred while verifying data: the data is tampered.")
		return err
	}
	return nil
}

func CompareBytes(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func loadDatastore(key userlib.UUID) (value []byte, err error) {
	value, ok := userlib.DatastoreGet(key)
	if !ok {
		err = errors.New("An error occurred while downloading data from Datastore: cannot find data correspoinding to UUID provided.")
		return nil, err
	}
	return value, nil
}

func GetHeaderUUID(username string, filename string) (headerUUID userlib.UUID, err error) {
	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("file-header/" + username))
	headerUUID, err = uuid.FromBytes(hash[:16])
	if err != nil {
		err = errors.New("An error occurred while generating file header UUID: " + err.Error())
	}
	return headerUUID, err
}

func GetContentUUID(username string, hashFilename []byte, part int) (contentUUID userlib.UUID, err error) {
	// Creates a UUID deterministically, from a sequence of bytes.
	tag := fmt.Sprintf("file-content/%v/%d/%s", hashFilename, part, username)
	hash := userlib.Hash([]byte(tag))
	contentUUID, err = uuid.FromBytes(hash[:16])
	if err != nil {
		err = errors.New("An error occurred while generating file content UUID: " + err.Error())
	}
	return contentUUID, err
}

type fileHeader struct {
	HashFileName   []byte       // Hash value of the file name
	Owner          bool         // Indicate whether the owner of this header is the owner of source file
	SourceHeader   userlib.UUID // File header of the source of current header
	ShareWith      []string     // Username the file is shared with
	SourceUserName string       // Username of the owner of source header
	Parts          int          // The number of parts of the file content
}

func findContentUUIDs(headerptr *fileHeader) (contentUUIDs []userlib.UUID, err error) {
	currentHeader := *headerptr
	for {
		if currentHeader.Owner {
			break
		}
		sig_nextHeader, err := loadDatastore(currentHeader.SourceHeader)
		if err != nil {
			return nil, err
		}
		verificationKey, ok := userlib.KeystoreGet(getVerifyKeyName(currentHeader.SourceUserName))
		if !ok {
			err = errors.New("An error occurred while login: The user is not initialized.")
			return nil, err
		}
		err = VerifySig(sig_nextHeader, verificationKey)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(sig_nextHeader[sigLength:], &currentHeader)
		if err != nil {
			return nil, err
		}
	}
	for i := 0; i < currentHeader.Parts; i++ {
		headerUUID, err := GetContentUUID(currentHeader.SourceUserName, currentHeader.HashFileName, i)
		if err != nil {
			return nil, err
		}
		contentUUIDs = append(contentUUIDs, headerUUID)
	}

	return contentUUIDs, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var (
		encKey       []byte
		macKey       []byte
		header       fileHeader
		headerUUID   userlib.UUID
		contentUUIDs []userlib.UUID
	)

	// Generate header UUID
	headerUUID, err = GetHeaderUUID(userdata.Username, filename)
	if err != nil {
		return err
	}

	// Check whether we have the file storage
	exist := false
	_, ok := userdata.EncKeys[filename]
	if ok {
		exist = true
	}

	// Get the MAC key and symmetric encryption key
	if !exist {
		// Generate keys for encryption and authenticity
		if err != nil {
			return err
		}
		encKey, err = generateSymKey(userdata.sourceKey, userdata.Username+filename+"Enc", userlib.AESKeySizeBytes)
		if err != nil {
			return err
		}
		macKey, err = generateSymKey(userdata.sourceKey, userdata.Username+filename+"MAC", userlib.AESKeySizeBytes)
		if err != nil {
			return err
		}
		userdata.EncKeys[filename] = encKey
		userdata.MacKeys[filename] = macKey

		// Create header
		header.HashFileName = userlib.Hash([]byte(filename))
		header.Owner = true
		header.SourceHeader = uuid.Nil
		header.ShareWith = make([]string, 0)
		header.SourceUserName = userdata.Username
		header.Parts = 1
	} else {
		encKey, _ = userdata.EncKeys[filename]
		macKey, _ = userdata.MacKeys[filename]

		// Verify the header stored
		sig_header, err := loadDatastore(headerUUID)
		if err != nil {
			return err
		}
		verificationKey, _ := userlib.KeystoreGet(getVerifyKeyName(userdata.Username))
		err = VerifySig(sig_header, verificationKey)
		if err != nil {
			return err
		}
		err = json.Unmarshal(sig_header[sigLength:], &header)
		if err != nil {
			return err
		}

		// If the current user is not the owner of the file, find the true content UUID
		contentUUIDs, err = findContentUUIDs(&header)
		if err != nil {
			return err
		}
		// Authenticate the content stored
		for _, contentUUID := range contentUUIDs {
			content_stored, err := loadDatastore(contentUUID)
			if err != nil {
				return err
			}
			err = AuthenticateMac(content_stored, macKey)
			if err != nil {
				return err
			}
			// Delete the content previously stored
			userlib.DatastoreDelete(contentUUID)
		}
		// Change the header to store new file
		header.Parts = 1
	}
	// Get the contentUUID
	contentUUID, err := GetContentUUID(userdata.Username, header.HashFileName, 0)

	// Encrypt then authenticate the file content, store it to Datastore
	mac_cipher, err := encThenMac(content, encKey, macKey)
	if err != nil {
		return err
	}
	// msg := fmt.Sprintf("Storage: MAC key is %v, Encryption key is %v", macKey, encKey)
	// userlib.DebugMsg(msg)
	userlib.DatastoreSet(contentUUID, mac_cipher)
	// userlib.DebugMsg("Storage: Content UUID is " + contentUUID.String())

	// Store the file header to Datastore
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}
	sig_header, err := getSignedMsg(headerBytes, userdata.SignKey)
	userlib.DatastoreSet(headerUUID, sig_header)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var (
		header       fileHeader
		headerUUID   userlib.UUID
		contentUUIDs []userlib.UUID
	)
	headerUUID, err = GetHeaderUUID(userdata.Username, filename)
	verifyKey, ok := userlib.KeystoreGet(getVerifyKeyName(userdata.Username))
	if !ok {
		return nil, err
	}

	sig_headerBytes, ok := userlib.DatastoreGet(headerUUID)
	if !ok {
		err = errors.New("An error occurred while loading file: cannot get file due to some malicious actions.")
		return nil, err
	}
	err = VerifySig(sig_headerBytes, verifyKey)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(sig_headerBytes[sigLength:], &header)
	if err != nil {
		return nil, err
	}

	contentUUIDs, err = findContentUUIDs(&header)
	// userlib.DebugMsg("Load: Content UUID is " + contentUUID.String())
	if err != nil {
		return nil, err
	}
	for _, contentUUID := range contentUUIDs {
		mac_cipher, ok := userlib.DatastoreGet(contentUUID)
		if !ok {
			err = errors.New("An error occurred while loading file: cannot get file due to some malicious actions.")
			return nil, err
		}
		macKey, ok := userdata.MacKeys[filename]
		if !ok {
			err = errors.New("An error occurred while loading file: the file does not exist.")
			return nil, err
		}
		err = AuthenticateMac(mac_cipher, macKey)
		if err != nil {
			return
		}
		cipher := mac_cipher[macLength:]
		content = append(content, userlib.SymDec(userdata.EncKeys[filename], cipher)...)
	}

	return content, nil
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
