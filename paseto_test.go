package backendpakarbi

import (
	"fmt"
	"testing"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

func TestCreateNewUserRole(t *testing.T) {
	var userdata User
	userdata.Username = "1214020"
	userdata.Email = "farhanrizki101010@gmail.com"
	userdata.Password = "testpass"
	userdata.PasswordHash = "testpass"
	userdata.Role = "user"
	mconn := SetConnection("MONGOSTRING", "TestPakArbi")
	CreateNewUserRole(mconn, "user", userdata)
}

func TestCreateNewAdminRole(t *testing.T) {
	var admindata Admin
	admindata.Username = "admin"
	admindata.Password = "admin"
	admindata.PasswordHash = "admin"
	admindata.Role = "admin"
	mconn := SetConnection("MONGOSTRING", "TestPakArbi")
	CreateNewAdminRole(mconn, "admin", admindata)
}

// func TestDeleteUser(t *testing.T) {
// 	mconn := SetConnection("MONGOSTRING", "pasabar13")
// 	var userdata User
// 	userdata.Username = "lolz"
// 	DeleteUser(mconn, "user", userdata)
// }

func CreateNewUserToken(t *testing.T) {
	var userdata User
	userdata.Username = "1214020"
	userdata.Password = "testpass"
	userdata.PasswordHash = "testpass"
	userdata.Role = "user"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "TestPakArbi")

	// Call the function to create a user and generate a token
	err := CreateUserAndAddToken("your_private_key_env", mconn, "user", userdata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

func CreateNewAdminToken(t *testing.T) {
	var userdata User
	userdata.Username = "admin"
	userdata.Password = "admin123"
	userdata.Role = "admin"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "PakArbi")

	// Call the function to create a user and generate a token
	err := CreateUserAndAddToken("your_private_key_env", mconn, "user", userdata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

func TestGFCPostHandlerUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "TestPakArbi")
	var userdata User
	userdata.Username = "1214020"
	userdata.Password = "testpass"
	userdata.PasswordHash = "testpass"
	userdata.Role = "user"
	CreateNewUserRole(mconn, "user", userdata)
}

func TestGeneratePasswordHash(t *testing.T) {
	password := "testpass"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)
	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
}

func TestGenerateAdminPasswordHash(t *testing.T) {
	passwordhash := "admin"
	hash, _ := HashPassword(passwordhash) // ignore error for the sake of simplicity

	fmt.Println("Password:", passwordhash)
	fmt.Println("Hash:    ", hash)
	match := CheckPasswordHash(passwordhash, hash)
	fmt.Println("Match:   ", match)
}

func TestGeneratePrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("testpass", privateKey)
	fmt.Println(hasil, err)
}

func TestGenerateAdminPrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("admin", privateKey)
	fmt.Println(hasil, err)
}

func TestHashFunction(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "TestPakArbi")
	var userdata User
	userdata.Username = "1214020"
	userdata.Password = "testpass"
	userdata.PasswordHash = "testpass"

	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mconn, "user", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPassword(userdata.PasswordHash)
	fmt.Println("Hash Password : ", hash)
	match := CheckPasswordHash(userdata.PasswordHash, res.PasswordHash)
	fmt.Println("Match:   ", match)

}

func TestHashAdminFunction(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var admindata Admin
	admindata.Username = "admin"
	admindata.Email = "admin@gmail.com"
	admindata.Password = "admin"

	filterUsername := bson.M{"username": admindata.Username}
	filterEmail := bson.M{"email": admindata.Email}

	resByUsername := atdb.GetOneDoc[Admin](mconn, "admin", filterUsername)
	resByEmail := atdb.GetOneDoc[Admin](mconn, "admin", filterEmail)

	fmt.Println("Mongo User Result (by username): ", resByUsername)
	fmt.Println("Mongo User Result (by email): ", resByEmail)

	hash, _ := HashPassword(admindata.Password)
	fmt.Println("Hash Password : ", hash)

	matchByUsername := CheckPasswordHash(admindata.Password, resByUsername.Password)
	matchByEmail := CheckPasswordHash(admindata.Password, resByEmail.Password)

	fmt.Println("Match (by username):   ", matchByUsername)
	fmt.Println("Match (by email):   ", matchByEmail)
}

func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.Username = "1214020"
	userdata.Password = "testpass"
	userdata.PasswordHash = "testpass"

	anu := IsPasswordValid(mconn, "user", userdata)
	fmt.Println(anu)
}

func TestUserFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.Username = "1214020"
	userdata.Password = "testpass"
	userdata.PasswordHash = "testpass"
	userdata.Role = "user"
	CreateUser(mconn, "user", userdata)
}

// func TestIsAdminPasswordValid(t *testing.T) {
// 	mconn := SetConnection("MONGOSTRING", "PakArbi")
// 	var admindata User
// 	admindata.Username = "admin"
// 	admindata.Password = "admin"

// 	anu := IsPasswordValid(mconn, "user", admindata)
// 	fmt.Println(anu)
// }

func TestAdminFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var admindata Admin
	admindata.Username = "admin"
	admindata.Password = "admin"
	admindata.Role = "admin"
	CreateAdmin(mconn, "admin", admindata)
}
