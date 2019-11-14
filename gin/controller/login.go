package controller

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"time"
)

type User struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Login(c *gin.Context) {
	// TODO: move secret key to file
	// TODO: benchmark
	// TODO: reduce token life time
	var u User
	var err error
	if err = c.ShouldBind(&u); err != nil {
		c.AbortWithStatus(500)
		return
	}
	if u.Username == "" || u.Password == "" {
		c.AbortWithStatusJSON(400, gin.H{
			"error": "username or password is empty",
		})
		return
	}
	var user = &models.User{Username: u.Username}
	if err := user.GetByUsername(); err != nil {
		c.AbortWithStatusJSON(404, gin.H{
			"error": "user not found",
		})
		return
	}
	if ok := user.CheckPassword(u.Password); !ok {
		c.AbortWithStatusJSON(404, gin.H{
			"error": "username or password is incorrect",
		})
		return
	}
	claims := Claims{Username: user.Username, StandardClaims: jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Minute * 500).Unix(),
	}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("https://osg.uz"))
	c.JSON(200, gin.H{
		"token": tokenString,
	})
	return
}
