package gin

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"time"
)

type claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type userModel struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User interface {
	GetUser(username string) error
	GetUsername() string
	GetPassword() string
	CheckPassword(password string) bool
}

type Authenticate struct {
	SecretKey string
	User      User
}

func NewAuthenticate(secretKey string, user User) *Authenticate {
	return &Authenticate{
		SecretKey: secretKey,
		User:      user,
	}
}

func (a Authenticate) LoginController(c *gin.Context) {
	var err error
	var user userModel
	err = c.BindJSON(&user)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "username or password is empty",
		})
		return
	}
	if user.Username == "" || user.Password == "" {
		c.JSON(400, gin.H{
			"error": "username or password is empty",
		})
		return
	}
	err = a.User.GetUser(user.Username)
	if err != nil {
		c.JSON(500, gin.H{
			"error": err.Error(),
		})
		return
	}
	if ok := a.User.CheckPassword(user.Password); !ok {
		c.JSON(400, gin.H{
			"error": "username or password is incorrect",
		})
		return
	}
	claims := claims{
		Username: user.Username, StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 30).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(a.SecretKey))
	c.JSON(200, gin.H{
		"token": tokenString,
	})
	return
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
