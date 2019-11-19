To install: ```go get -u github.com/protimaru/go-authenticate```
# Example for ```gin framework```
```go
package main

import (
    "fmt"
    goAuth "github.com/protimaru/go-authenticate"
    "github.com/gin-gonic/gin"
)

type User struct {
    Username string
    Password string
}

func (u *User) GetUser(username string) error {
    stmt, err := db.PrepareNamed()
    
}

/* 
    User struct must have these methods:
    * GetUser(string) error
    * GetUsername() string
    * GetPassword() string
    * CheckPassword(string) bool
*/

func main() {
    r := gin.New()
    auth := goAuth.NewAuthenticate("secret_key", &User{})
    r.POST("/login", auth.LoginController)
    r.Use(auth.Middleware())
}
```
