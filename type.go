package backendpakarbi

type User struct {
	Username     string `json:"username" bson:"username"`
	NPM          string `json:"npm" bson:"npm"`
	Password     string `json:"password" bson:"password"`
	PasswordHash string `json:"passwordhash" bson:"passwordhash"`
	Email        string `bson:"email,omitempty" json:"email,omitempty"`
	Role         string `json:"role,omitempty" bson:"role,omitempty"`
	Token        string `json:"token,omitempty" bson:"token,omitempty"`
	Private      string `json:"private,omitempty" bson:"private,omitempty"`
	Public       string `json:"public,omitempty" bson:"public,omitempty"`
}

type Credential struct {
	Status  bool   `json:"status" bson:"status"`
	Token   string `json:"token,omitempty" bson:"token,omitempty"`
	Message string `json:"message,omitempty" bson:"message,omitempty"`
}

type Response struct {
	Status  bool        `json:"status" bson:"status"`
	Message string      `json:"message" bson:"message"`
	Data    interface{} `json:"data" bson:"data"`
}
