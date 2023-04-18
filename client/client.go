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
	FilenameMap   map[userlib.UUID]string
}

type Identity struct {
	IdentityKey []byte
	Salt        []byte
}

func generateSymKey(sourceKey []byte, purpose []byte, keySize int) (newKey []byte, err error) {
	newKey, err = userlib.HashKDF(sourceKey, purpose)
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
	userdata.structEncKey, err = generateSymKey(userdata.sourceKey, []byte("structEncKey"), userlib.AESKeySizeBytes)
	if err != nil {
		return nil, err
	}
	userdata.structMacKey, err = generateSymKey(userdata.sourceKey, []byte("structMacKey"), userlib.AESKeySizeBytes)
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
	userdata.FilenameMap = make(map[uuid.UUID]string)

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

	// Initialize and store empty source table
	sourceTable := make(map[userlib.UUID]userlib.UUID)
	sourceTableBytes, err := json.Marshal(sourceTable)
	if err != nil {
		return nil, err
	}
	sig_sourceTableBytes, err := getSignedMsg(sourceTableBytes, userdata.SignKey)
	if err != nil {
		return nil, err
	}
	sourceTableUUID, err := GetSourceTableUUID(userdata.Username)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(sourceTableUUID, sig_sourceTableBytes)

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
	structEncKey, err := generateSymKey(sourceKey, []byte("structEncKey"), userlib.AESKeySizeBytes)
	if err != nil {
		return nil, err
	}
	structMacKey, err := generateSymKey(sourceKey, []byte("structMacKey"), userlib.AESKeySizeBytes)
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

func GetHeaderUUID(username string, hashFilename []byte) (headerUUID userlib.UUID, err error) {
	// Creates a UUID deterministically, from a sequence of bytes.
	tag := fmt.Sprintf("file-header/%v/%s", hashFilename, username)
	hash := userlib.Hash([]byte(tag))
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

func GetLocationUUID(username string, hashFilename []byte) (locationUUID userlib.UUID, err error) {
	// Creates a UUID deterministically, from a sequence of bytes.
	tag := fmt.Sprintf("file-location/%v/%s", hashFilename, username)
	hash := userlib.Hash([]byte(tag))
	locationUUID, err = uuid.FromBytes(hash[:16])
	if err != nil {
		err = errors.New("An error occurred while generating file location UUID: " + err.Error())
	}
	return locationUUID, err
}

func GetSourceTableUUID(username string) (sourceTableUUID userlib.UUID, err error) {
	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-filesource/" + username))
	sourceTableUUID, err = uuid.FromBytes(hash[:16])
	if err != nil {
		err = errors.New("An error occurred while generating source table UUID: " + err.Error())
	}
	return sourceTableUUID, err
}

type fileHeader struct {
	HashFileName   []byte       // Hash value of the file name
	Owner          bool         // Indicate whether the owner of this header is the owner of source file
	SourceHeader   userlib.UUID // File header of the source of current header
	ShareWith      []string     // Username the file is shared with
	SourceUserName string       // Username of the owner of source header
}

func findContentLocations(headerptr *fileHeader, macKey []byte) (locationUUID userlib.UUID, sourceHeader userlib.UUID, locations []userlib.UUID, err error) {
	currentHeader := *headerptr
	for {
		if currentHeader.Owner {
			break
		}
		sourceHeader = currentHeader.SourceHeader
		sig_nextHeader, err := loadDatastore(sourceHeader)
		if err != nil {
			return uuid.Nil, uuid.Nil, nil, err
		}
		verificationKey, ok := userlib.KeystoreGet(getVerifyKeyName(currentHeader.SourceUserName))
		if !ok {
			err = errors.New("An error occurred while login: The user is not initialized.")
			return uuid.Nil, uuid.Nil, nil, err
		}
		err = VerifySig(sig_nextHeader, verificationKey)
		if err != nil {
			return uuid.Nil, uuid.Nil, nil, err
		}
		err = json.Unmarshal(sig_nextHeader[sigLength:], &currentHeader)
		if err != nil {
			return uuid.Nil, uuid.Nil, nil, err
		}
	}
	locationUUID = currentHeader.SourceHeader
	mac_locationBytes, err := loadDatastore(locationUUID)
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	err = AuthenticateMac(mac_locationBytes, macKey)
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	err = json.Unmarshal(mac_locationBytes[macLength:], &locations)
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	return locationUUID, sourceHeader, locations, nil
}

func findSourceUsername(headerptr *fileHeader) (sourceUsername string, err error) {
	currentHeader := *headerptr
	for {
		if currentHeader.Owner {
			break
		}
		sourceHeader := currentHeader.SourceHeader
		sig_nextHeader, err := loadDatastore(sourceHeader)
		if err != nil {
			return sourceUsername, err
		}
		verificationKey, ok := userlib.KeystoreGet(getVerifyKeyName(currentHeader.SourceUserName))
		if !ok {
			err = errors.New("An error occurred while login: The user is not initialized.")
			return sourceUsername, err
		}
		err = VerifySig(sig_nextHeader, verificationKey)
		if err != nil {
			return sourceUsername, err
		}
		err = json.Unmarshal(sig_nextHeader[sigLength:], &currentHeader)
		if err != nil {
			return sourceUsername, err
		}
	}
	sourceUsername = currentHeader.SourceUserName
	return sourceUsername, nil
}

func (userdata *User) SyncUser() (err error) {
	// Check the updates
	// 1. Load the source table
	sourceTableUUID, err := GetSourceTableUUID(userdata.Username)
	if err != nil {
		return err
	}
	sig_sourceTableBytes, err := loadDatastore(sourceTableUUID)
	if err != nil {
		return err
	}
	verifyKey, _ := userlib.KeystoreGet(getVerifyKeyName(userdata.Username))
	err = VerifySig(sig_sourceTableBytes, verifyKey)
	if err != nil {
		return err
	}
	var sourceTable map[userlib.UUID]userlib.UUID
	err = json.Unmarshal(sig_sourceTableBytes[sigLength:], &sourceTable)
	if err != nil {
		return err
	}
	// Receive updates from every source
	var (
		header fileHeader
		update Invitation
	)
	for sourceHeaderUUID, headerUUID := range sourceTable {
		// Get the update
		updateUUID, err := GetUpdateUUID(userdata.Username, sourceHeaderUUID)
		if err != nil {
			return err
		}
		sig_cipher, ok := userlib.DatastoreGet(updateUUID)
		if !ok {
			continue
		}

		// Get the sender's verification key
		// 1. Find the sender's username
		sig_headerBytes, err := loadDatastore(headerUUID)
		if err != nil {
			return err
		}
		err = VerifySig(sig_headerBytes, verifyKey)
		if err != nil {
			return err
		}
		err = json.Unmarshal(sig_headerBytes[sigLength:], &header)
		if err != nil {
			return err
		}
		senderUsername, err := findSourceUsername(&header)
		if err != nil {
			return err
		}
		// 2. Get the verification key
		senderVerifyKey, ok := userlib.KeystoreGet(getVerifyKeyName(senderUsername))
		if !ok {
			err = errors.New("An error occurred while updating user's key: cannot verify the update information.")
			return err
		}

		// Verify the update and decrypt it
		err = VerifySig(sig_cipher, senderVerifyKey)
		if err != nil {
			return err
		}
		updateBytes, err := userlib.PKEDec(userdata.PrivateDecKey, sig_cipher[sigLength:])
		if err != nil {
			err = errors.New("An error occurred while updating the keys: fail to decrypt the update inforamtion.")
			return err
		}
		err = json.Unmarshal(updateBytes, &update)
		if err != nil {
			return err
		}
		// userlib.DebugMsg("Update keys for %s", userdata.FilenameMap[headerUUID])
		// userlib.DebugMsg("Old Encryption Key: %v; Old MAC Key: %v", userdata.EncKeys[userdata.FilenameMap[headerUUID]], userdata.MacKeys[userdata.FilenameMap[headerUUID]])
		// userlib.DebugMsg("New Encryption Key: %v; New MAC Key: %v", update.EncKey, update.MacKey)
		userdata.EncKeys[userdata.FilenameMap[headerUUID]] = update.EncKey
		userdata.MacKeys[userdata.FilenameMap[headerUUID]] = update.MacKey
		userStructBytes, err := json.Marshal(userdata)
		if err != nil {
			return err
		}
		mac_value_pair, err := encThenMac(userStructBytes, userdata.structEncKey, userdata.structMacKey)
		if err != nil {
			return err
		}
		userUUID, err := GetUserUUID(userdata.Username)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(userUUID, mac_value_pair)
	}

	var newState User
	structMacKey := userdata.structMacKey
	structEncKey := userdata.structEncKey
	userUUID, err := GetUserUUID(userdata.Username)
	if err != nil {
		return err
	}
	mac_userStruct, err := loadDatastore(userUUID)
	if err != nil {
		return err
	}
	err = AuthenticateMac(mac_userStruct, structMacKey)
	if err != nil {
		return err
	}
	cipherStruct := mac_userStruct[macLength:]
	userStructBytes := userlib.SymDec(structEncKey, cipherStruct)
	err = json.Unmarshal(userStructBytes, &newState)
	if err != nil {
		return err
	}
	userdata.MacKeys = newState.MacKeys
	userdata.EncKeys = newState.EncKeys
	userdata.FilenameMap = newState.FilenameMap
	// userlib.DebugMsg("After sync ---- New Encryption Key: %v; New MAC Key: %v", userdata.EncKeys, userdata.MacKeys)
	return nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	err = userdata.SyncUser()
	if err != nil {
		err = errors.New("An error occurred while updating user structure: " + err.Error())
	}
	var (
		encKey     []byte
		macKey     []byte
		header     fileHeader
		headerUUID userlib.UUID
	)

	// Generate UUIDs
	headerUUID, err = GetHeaderUUID(userdata.Username, userlib.Hash([]byte(filename)))
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
		encKey, err = generateSymKey(userdata.sourceKey, []byte(userdata.Username+filename+"Enc"), userlib.AESKeySizeBytes)
		if err != nil {
			return err
		}
		macKey, err = generateSymKey(userdata.sourceKey, []byte(userdata.Username+filename+"MAC"), userlib.AESKeySizeBytes)
		if err != nil {
			return err
		}
		userdata.EncKeys[filename] = encKey
		userdata.MacKeys[filename] = macKey
		userdata.FilenameMap[headerUUID] = filename

		// Store the updated user structure
		userStructBytes, err := json.Marshal(userdata)
		if err != nil {
			return err
		}
		mac_value_pair, err := encThenMac(userStructBytes, userdata.structEncKey, userdata.structMacKey)
		if err != nil {
			return err
		}
		userUUID, err := GetUserUUID(userdata.Username)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(userUUID, mac_value_pair)

		// Create and store the header
		header.HashFileName = userlib.Hash([]byte(filename))
		header.Owner = true
		locationUUID, err := GetLocationUUID(userdata.Username, userlib.Hash([]byte(filename)))
		if err != nil {
			return err
		}
		header.SourceHeader = locationUUID
		header.ShareWith = make([]string, 0)
		header.SourceUserName = userdata.Username
		headerBytes, err := json.Marshal(header)
		if err != nil {
			return err
		}
		sig_header, err := getSignedMsg(headerBytes, userdata.SignKey)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(headerUUID, sig_header)

		// Store the content
		contentUUID, err := GetContentUUID(userdata.Username, userlib.Hash([]byte(filename)), 0)
		if err != nil {
			return err
		}
		mac_cipher, err := encThenMac(content, encKey, macKey)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(contentUUID, mac_cipher)

		// Store the location
		var location []userlib.UUID
		location = append(location, contentUUID)
		locationBytes, err := json.Marshal(location)
		if err != nil {
			return err
		}
		mac, err := userlib.HMACEval(macKey, locationBytes)
		if err != nil {
			return err
		}
		mac_locationBytes := append(mac, locationBytes...)
		userlib.DatastoreSet(locationUUID, mac_locationBytes)

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
		locationUUID, _, location, err := findContentLocations(&header, macKey)
		if err != nil {
			return err
		}
		// Authenticate the content stored
		for _, contentUUID := range location {
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

		// Store the content
		contentUUID := location[0]
		if err != nil {
			return err
		}
		mac_cipher, err := encThenMac(content, encKey, macKey)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(contentUUID, mac_cipher)

		// Store the location
		var emptyList []userlib.UUID
		location = append(emptyList, contentUUID)
		locationBytes, err := json.Marshal(location)
		if err != nil {
			return err
		}
		mac, err := userlib.HMACEval(macKey, locationBytes)
		if err != nil {
			return nil
		}
		mac_locationBytes := append(mac, locationBytes...)
		userlib.DatastoreSet(locationUUID, mac_locationBytes)
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var (
		err        error
		encKey     []byte
		macKey     []byte
		header     fileHeader
		headerUUID userlib.UUID
		location   []userlib.UUID
	)
	err = userdata.SyncUser()
	if err != nil {
		err = errors.New("An error occurred while updating user structure: " + err.Error())
		return err
	}

	// Generate macKey and encKey
	encKey, ok := userdata.EncKeys[filename]
	if !ok {
		err = errors.New("An error occurred while appending to file: the file does not exist.")
		return err
	}
	macKey, ok = userdata.MacKeys[filename]
	if !ok {
		err = errors.New("An error occurred while appending to file: the file does not exist.")
		return err
	}

	// Get the header file
	headerUUID, err = GetHeaderUUID(userdata.Username, userlib.Hash([]byte(filename)))
	if err != nil {
		return err
	}
	verifyKey, ok := userlib.KeystoreGet(getVerifyKeyName(userdata.Username))
	if !ok {
		return nil
	}
	sig_headerBytes, err := loadDatastore(headerUUID)
	if err != nil {
		return nil
	}
	err = VerifySig(sig_headerBytes, verifyKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(sig_headerBytes[sigLength:], &header)
	if err != nil {
		return nil
	}

	// Get the locations of the file content
	locationUUID, _, location, err := findContentLocations(&header, macKey)
	if err != nil {
		return err
	}

	// Store the new content
	contentUUID, err := GetContentUUID(userdata.Username, userlib.Hash([]byte(filename)), len(location))
	if err != nil {
		return err
	}
	mac_cipher, err := encThenMac(content, encKey, macKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(contentUUID, mac_cipher)

	// Store the new location
	location = append(location, contentUUID)
	locationBytes, err := json.Marshal(location)
	if err != nil {
		return err
	}
	mac, err := userlib.HMACEval(macKey, locationBytes)
	if err != nil {
		return nil
	}
	mac_locationBytes := append(mac, locationBytes...)
	userlib.DatastoreSet(locationUUID, mac_locationBytes)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	err = userdata.SyncUser()
	if err != nil {
		err = errors.New("An error occurred while updating user structure: " + err.Error())
	}
	var (
		header     fileHeader
		headerUUID userlib.UUID
		locations  []userlib.UUID
	)
	macKey, ok := userdata.MacKeys[filename]
	// userlib.DebugMsg("Loading file ---- the MAC Key is: %v", macKey)
	if !ok {
		err = errors.New("An error occurred while loading file: the file does not exist.")
		return nil, err
	}

	headerUUID, err = GetHeaderUUID(userdata.Username, userlib.Hash([]byte(filename)))
	verifyKey, ok := userlib.KeystoreGet(getVerifyKeyName(userdata.Username))
	if !ok {
		return nil, err
	}

	sig_headerBytes, err := loadDatastore(headerUUID)
	if err != nil {
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

	_, _, locations, err = findContentLocations(&header, macKey)
	if err != nil {
		return nil, err
	}
	for _, contentUUID := range locations {
		mac_cipher, err := loadDatastore(contentUUID)
		if err != nil {
			return nil, err
		}
		err = AuthenticateMac(mac_cipher, macKey)
		if err != nil {
			return nil, err
		}
		cipher := mac_cipher[macLength:]
		content = append(content, userlib.SymDec(userdata.EncKeys[filename], cipher)...)
	}

	return content, nil
}

type Invitation struct {
	EncKey []byte
	MacKey []byte
	Source userlib.UUID
}

func GetInvitationUUID(username string, hashFilename []byte) (invitationUUID userlib.UUID, err error) {
	// Creates a UUID deterministically, from a sequence of bytes.
	tag := fmt.Sprintf("file-invitation/%v/%s", hashFilename, username)
	hash := userlib.Hash([]byte(tag))
	invitationUUID, err = uuid.FromBytes(hash[:16])
	if err != nil {
		err = errors.New("An error occurred while generating invitation UUID: " + err.Error())
	}
	return invitationUUID, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	var (
		invitation Invitation
		ok         bool
		headerUUID userlib.UUID
		header     fileHeader
	)
	// Update the user session
	userdata.SyncUser()

	// Create the invitation
	invitation.EncKey, ok = userdata.EncKeys[filename]
	if !ok {
		err = errors.New("An error occurred while creating invitation: the file does not exist.")
		return uuid.Nil, err
	}
	invitation.MacKey, ok = userdata.MacKeys[filename]
	if !ok {
		err = errors.New("An error occurred while creating invitation: the file does not exist.")
		return uuid.Nil, err
	}
	invitation.Source, err = GetHeaderUUID(userdata.Username, userlib.Hash([]byte(filename)))
	if err != nil {
		return uuid.Nil, err
	}

	// Generate the uuid of invitation and store it to Datastore
	invitationPtr, err = GetInvitationUUID(userdata.Username, userlib.Hash([]byte(filename)))
	if err != nil {
		return uuid.Nil, err
	}
	// Encrypt the invitation with the recipient's public key
	encKey, ok := userlib.KeystoreGet(getPEKeyName(recipientUsername))
	if !ok {
		err = errors.New("An error occurred while creating invitation: the recipient does not exist.")
		return uuid.Nil, err
	}
	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}
	cipher, err := userlib.PKEEnc(encKey, invitationBytes)
	if err != nil {
		return uuid.Nil, err
	}
	sig_cipher, err := getSignedMsg(cipher, userdata.SignKey)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invitationPtr, sig_cipher)

	// Update the user ShareWith list in the fileheader
	headerUUID, err = GetHeaderUUID(userdata.Username, userlib.Hash([]byte(filename)))
	verifyKey, ok := userlib.KeystoreGet(getVerifyKeyName(userdata.Username))
	if !ok {
		return uuid.Nil, err
	}
	sig_headerBytes, err := loadDatastore(headerUUID)
	if err != nil {
		return uuid.Nil, err
	}
	err = VerifySig(sig_headerBytes, verifyKey)
	if err != nil {
		return uuid.Nil, err
	}
	err = json.Unmarshal(sig_headerBytes[sigLength:], &header)
	if err != nil {
		return uuid.Nil, err
	}
	header.ShareWith = append(header.ShareWith, recipientUsername)
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return uuid.Nil, err
	}
	sig_headerBytes, err = getSignedMsg(headerBytes, userdata.SignKey)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(headerUUID, sig_headerBytes)
	// userlib.DebugMsg("After creating the invitation, share with: %v", header.ShareWith)

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	var (
		invitation Invitation
		err        error
		ok         bool
		header     fileHeader
	)

	// Check whether the filename exists
	_, ok = userdata.EncKeys[filename]
	if ok {
		err = errors.New("An error occurred while accepting invitation: the file already exists.")
		return err
	}

	// Verify and decrypt the invitation
	sig_cipher, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		err = errors.New("An error occurred while accepting invitaion: the invitation does not exist.")
		return err
	}
	verifyKey, ok := userlib.KeystoreGet(getVerifyKeyName(senderUsername))
	if !ok {
		err = errors.New("An error occurred while accepting invitation: the sender's user name is invalid.")
		return err
	}
	err = VerifySig(sig_cipher, verifyKey)
	if err != nil {
		return err
	}
	invitationBytes, err := userlib.PKEDec(userdata.PrivateDecKey, sig_cipher[sigLength:])
	if err != nil {
		return err
	}
	err = json.Unmarshal(invitationBytes, &invitation)
	if err != nil {
		return err
	}

	// Create a new header and store it
	header.HashFileName = userlib.Hash([]byte(filename))
	header.Owner = false
	header.SourceHeader = invitation.Source
	header.ShareWith = make([]string, 0)
	header.SourceUserName = senderUsername
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}
	sig_header, err := getSignedMsg(headerBytes, userdata.SignKey)
	if err != nil {
		return err
	}
	headerUUID, err := GetHeaderUUID(userdata.Username, header.HashFileName)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(headerUUID, sig_header)

	// Store the new keys into user structure
	userdata.EncKeys[filename] = invitation.EncKey
	userdata.MacKeys[filename] = invitation.MacKey
	userdata.FilenameMap[headerUUID] = filename
	// Store the update user structure
	userStructBytes, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	mac_value_pair, err := encThenMac(userStructBytes, userdata.structEncKey, userdata.structMacKey)
	if err != nil {
		return err
	}
	userUUID, err := GetUserUUID(userdata.Username)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userUUID, mac_value_pair)

	// Delete the invitation once it is accepted
	userlib.DatastoreDelete(invitationPtr)

	// Update the source table
	sourceTableUUID, err := GetSourceTableUUID(userdata.Username)
	if err != nil {
		return err
	}
	sig_sourceTableBytes, err := loadDatastore(sourceTableUUID)
	if err != nil {
		return err
	}
	verifyKey, _ = userlib.KeystoreGet(getVerifyKeyName(userdata.Username))
	err = VerifySig(sig_sourceTableBytes, verifyKey)
	if err != nil {
		return err
	}
	var sourceTable map[userlib.UUID]userlib.UUID
	err = json.Unmarshal(sig_sourceTableBytes[sigLength:], &sourceTable)
	if err != nil {
		return err
	}
	_, sourceHeader, _, err := findContentLocations(&header, userdata.MacKeys[filename])
	if err != nil {
		return err
	}
	sourceTable[sourceHeader] = headerUUID
	sourceTableBytes, err := json.Marshal(sourceTable)
	if err != nil {
		return err
	}
	sig_sourceTableBytes, err = getSignedMsg(sourceTableBytes, userdata.SignKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(sourceTableUUID, sig_sourceTableBytes)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	userdata.SyncUser()

	var (
		ok        bool
		err       error
		oldEncKey []byte
		oldMacKey []byte
		newEncKey []byte
		newMacKey []byte
		header    fileHeader
	)

	// Check whether the filename exists
	oldEncKey, ok = userdata.EncKeys[filename]
	if !ok {
		err = errors.New("An error occurred while revoking access: the file does not exist.")
		return err
	}
	oldMacKey, ok = userdata.MacKeys[filename]
	if !ok {
		err = errors.New("An error occurred while revoking access: the file does not exist.")
		return err
	}

	// Check whether the user is shared with the file.
	headerUUID, err := GetHeaderUUID(userdata.Username, userlib.Hash([]byte(filename)))
	verifyKey, ok := userlib.KeystoreGet(getVerifyKeyName(userdata.Username))
	if !ok {
		return err
	}
	sig_headerBytes, err := loadDatastore(headerUUID)
	if err != nil {
		return err
	}
	err = VerifySig(sig_headerBytes, verifyKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(sig_headerBytes[sigLength:], &header)
	if err != nil {
		return err
	}
	have_access := false
	idx := 0
	for _, shareUser := range header.ShareWith {
		if shareUser == recipientUsername {
			have_access = true
			break
		}
		idx++
	}
	if !have_access {
		err = errors.New("An error occurred while revoking access: the file is not shared with recipient.")
		return err
	}
	// Delete the recipient from the ShareWith list
	header.ShareWith = append(header.ShareWith[:idx], header.ShareWith[idx+1:]...)
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}
	sig_header, err := getSignedMsg(headerBytes, userdata.SignKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(headerUUID, sig_header)

	// Encrypt and authenticate the file content with new encryption and MAC key
	random_bytes := userlib.RandomBytes(userlib.AESKeySizeBytes)
	newEncKey, err = generateSymKey(userdata.sourceKey, append([]byte(userdata.Username+filename+"Enc"), random_bytes...), userlib.AESKeySizeBytes)
	newMacKey, err = generateSymKey(userdata.sourceKey, append([]byte(userdata.Username+filename+"Mac"), random_bytes...), userlib.AESKeySizeBytes)
	locationUUID, _, locations, err := findContentLocations(&header, oldMacKey)
	if err != nil {
		return err
	}
	for _, contentUUID := range locations {
		mac_cipher, err := loadDatastore(contentUUID)
		if err != nil {
			return err
		}
		err = AuthenticateMac(mac_cipher, oldMacKey)
		if err != nil {
			return err
		}
		content := userlib.SymDec(oldEncKey, mac_cipher[macLength:])
		// userlib.DebugMsg("Revoke Access ---- the content is: %s", content)
		// Encrypt and authenticate with new keys
		new_mac_cipher, err := encThenMac(content, newEncKey, newMacKey)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(contentUUID, new_mac_cipher)
	}

	// Save the new keys
	userdata.EncKeys[filename] = newEncKey
	userdata.MacKeys[filename] = newMacKey
	// userlib.DebugMsg("Old Encryption Key: %v; Old MAC Key: %v", oldEncKey, oldMacKey)
	// userlib.DebugMsg("After revoke ---- New Encryption Key: %v; New MAC Key: %v", newEncKey, newMacKey)
	userStructBytes, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	mac_cipher, err := encThenMac(userStructBytes, userdata.structEncKey, userdata.structMacKey)
	if err != nil {
		return err
	}
	userUUID, err := GetUserUUID(userdata.Username)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userUUID, mac_cipher)

	// Use the new MAC key to generate new MAC for locations
	locationBytes, err := json.Marshal(locations)
	if err != nil {
		return err
	}
	mac, err := userlib.HMACEval(newMacKey, locationBytes)
	if err != nil {
		return err
	}
	mac_locationBytes := append(mac, locationBytes...)
	userlib.DatastoreSet(locationUUID, mac_locationBytes)

	// Create update information to the user who still have access to the file
	var sharedUser []string
	err = findSharedUsers(&header, headerUUID, &sharedUser)
	// userlib.DebugMsg("The shared users are: %v", sharedUser)

	// Create update information to all of the shared users
	for _, username := range sharedUser {
		updateUUID, err := GetUpdateUUID(username, headerUUID)
		if err != nil {
			return err
		}
		// Create the updates, which has the same fields as invitation
		var update Invitation
		update.EncKey = newEncKey
		update.MacKey = newMacKey
		update.Source = headerUUID
		// Store the updates to Datastore
		encKey, ok := userlib.KeystoreGet(getPEKeyName(username))
		if !ok {
			err = errors.New("An error occurred while creating invitation: the recipient does not exist.")
			return err
		}
		updateBytes, err := json.Marshal(update)
		if err != nil {
			return err
		}
		cipher, err := userlib.PKEEnc(encKey, updateBytes)
		if err != nil {
			return err
		}
		sig_cipher, err := getSignedMsg(cipher, userdata.SignKey)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(updateUUID, sig_cipher)
	}

	return nil
}

func findSharedUsers(rootHeader *fileHeader, sourceHeader userlib.UUID, sharedUser *[]string) (err error) {
	shareWith := rootHeader.ShareWith
	if len(shareWith) == 0 {
		return nil
	} else {
		for _, username := range shareWith {
			*sharedUser = append(*sharedUser, username)
			// Get the next user's verify key
			verifyKey, _ := userlib.KeystoreGet(getVerifyKeyName(username))
			// Get the next user's source table
			sourceTableUUID, err := GetSourceTableUUID(username)
			if err != nil {
				return err
			}
			sig_sourceTableBytes, err := loadDatastore(sourceTableUUID)
			if err != nil {
				return err
			}
			err = VerifySig(sig_sourceTableBytes, verifyKey)
			if err != nil {
				return err
			}
			var sourceTable map[userlib.UUID]userlib.UUID
			err = json.Unmarshal(sig_sourceTableBytes[sigLength:], &sourceTable)
			if err != nil {
				return err
			}
			// Get next user's headerUUID
			headerUUID, ok := sourceTable[sourceHeader]
			if !ok {
				err = errors.New("An error occurred while finding shared users: cannot find the next header UUID.")
				return err
			}
			// Get the next header
			sig_headerBytes, err := loadDatastore(headerUUID)
			if err != nil {
				return err
			}
			err = VerifySig(sig_headerBytes, verifyKey)
			if err != nil {
				return err
			}
			var header fileHeader
			err = json.Unmarshal(sig_headerBytes[sigLength:], &header)
			if err != nil {
				return err
			}
			err = findSharedUsers(&header, sourceHeader, sharedUser)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func GetUpdateUUID(username string, sourceHeader userlib.UUID) (updateUUID userlib.UUID, err error) {
	tag := fmt.Sprintf("user-update/%s/%v", username, sourceHeader)
	hash := userlib.Hash([]byte(tag))
	updateUUID, err = uuid.FromBytes(hash[:16])
	if err != nil {
		err = errors.New("An error occurred while generating updates UUID: " + err.Error())
	}
	return updateUUID, err
}
