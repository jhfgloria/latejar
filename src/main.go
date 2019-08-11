package main

import (
	"github.com/gin-gonic/gin"
	"log"
	"os"
)

func main() {
	router := gin.Default()

	router.POST("/auth/register")
	router.POST("/auth/sign-in")
	router.POST("/auth/logout")

	router.GET("/jars")        // get all jars
	router.POST("/jars")       // create jar
	router.GET("/jars/:id")    // get one jar
	router.PUT("/jars/:id")    // update one jar
	router.DELETE("/jars/:id") // delete one jar
	router.PATCH("/jars/:id")  // update jar's fine

	router.POST("/jars/:id/user/:id") // fine user

	router.POST("/jars/:id/invite") // invite user(s) to jar

	router.POST("/users/:id") // pay specific fine per user

	var port string
	if os.Getenv("PORT") == "" {
		port = "8000"
	} else {
		port = os.Getenv("PORT")
	}
	log.Fatal(router.Run(":" + port))
}
