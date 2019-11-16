To install: ```go get -u github.com/protimaru/go-authenticate```
# Example for ```gin framework```
```
package main

import (
    "fmt"
    goAuth "github.com/protimaru/go-authenticate"
    "github.com/gin-gionic/gin"
)

type User struct {
    Username string
    Password string
}

/* 
    User struct must have these methods:
    *GetUser(string) error
	*GetUsername() string
	*GetPassword() string
	*CheckPassword(string) bool 
*/

func main() {
    r := gin.New()
    auth := goAuth.NewAuthenticate("secret_key", )
    r.POST("/login", auth.LoginController)
    r.User(auth.Middleware())
}
```