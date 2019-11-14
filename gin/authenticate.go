package gin

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type User interface {
	getByUsername(string) interface{}
}

type Authenticate struct {
	SecretKey string
	User
}

func (a Authenticate) LoginController(c *gin.Context) {

}

func (a *Authenticate) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			c.AbortWithStatus(401)
			return
		}
		token, _ := jwt.Parse(authHeader, func(token *jwt.Token) (i interface{}, e error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("error")
			}
			return []byte(a.SecretKey), nil
		})
		if token == nil {
			c.AbortWithStatus(401)
			return
		}
		if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Next()
			return
		} else {
			c.AbortWithStatus(401)
			return
		}
	}
}
