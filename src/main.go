package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Middleware for authentication
func Authenticate() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		auth := ctx.Request.Header.Get("Authorization")

		if auth == "" {
			println("Missing authorization header")
			ctx.Writer.WriteHeader(http.StatusUnauthorized)
			ctx.Abort()
			return
		}

		auth = strings.Split(auth, "Bearer ")[1]

		claims := &LateJarClaims{}
		tkn, err := jwt.ParseWithClaims(auth, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			ctx.Writer.WriteHeader(http.StatusUnauthorized)
			ctx.Abort()
			return
		}
		if !tkn.Valid {
			ctx.Writer.WriteHeader(http.StatusUnauthorized)
			ctx.Abort()
			return
		}

		ctx.Request.Header.Add("principal", claims.Email)
		ctx.Next()
	}
}

var jwtKey = []byte("my-super-random-secret-key")

type LateJarClaims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func sign(password, salt string) string {
	var h = sha256.New()
	h.Write([]byte(salt + password))
	return hex.EncodeToString(h.Sum(nil))
}

func Register(db *sql.DB) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		b, err := ioutil.ReadAll(ctx.Request.Body)
		defer ctx.Request.Body.Close()

		if err != nil {
			log.Printf(err.Error())
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		payload := struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}{}
		err = json.Unmarshal(b, &payload)

		if err != nil {
			log.Printf(err.Error())
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "request should have name, email and password of type string"})
			return
		}

		// TODO: generate random salt
		salt := "potatorandom"
		password := sign(payload.Password, salt)
		var uid int
		err = db.QueryRow(
			"INSERT INTO users(email, name, password, salt) VALUES($1, $2, $3, $4) returning id;",
			payload.Email,
			payload.Name,
			password,
			salt,
		).Scan(&uid)

		if err != nil {
			log.Printf(err.Error())
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusCreated, gin.H{"id": uid})
	}
}

func SignIn(db *sql.DB) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		b, err := ioutil.ReadAll(ctx.Request.Body)
		defer ctx.Request.Body.Close()

		if err != nil {
			log.Printf(err.Error())
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		payload := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{}
		err = json.Unmarshal(b, &payload)

		if err != nil {
			log.Printf(err.Error())
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "request should have email and password of type string"})
			return
		}

		var salt string
		err = db.QueryRow("select salt from users where email=$1", payload.Email).Scan(&salt)

		if err != nil {
			log.Printf(err.Error())
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "email/password combination don't exist"})
			return
		}

		var email string
		password := sign(payload.Password, salt)
		err = db.QueryRow("select email from users where password=$1", password).Scan(&email)

		if err != nil {
			log.Printf(err.Error())
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "email/password combination don't exist"})
			return
		}

		expirationTime := time.Now().Add(30 * time.Minute)
		claims := &LateJarClaims{
			Email: payload.Email,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"token": tokenString})
		return
	}
}

func CreateJar(db *sql.DB) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		b, err := ioutil.ReadAll(ctx.Request.Body)
		defer ctx.Request.Body.Close()

		payload := struct {
			Name string `json:"name"`
		}{}
		err = json.Unmarshal(b, &payload)

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "name of type string expected"})
			return
		}

		tx, err := db.Begin()
		if tx == nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
			return
		}

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			_ = tx.Rollback()
			return
		}

		var uid string
		err = db.QueryRow("select id from users where email=$1", ctx.GetHeader("principal")).Scan(&uid)

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			_ = tx.Rollback()
			return
		}

		var jid int
		err = db.QueryRow(
			"INSERT INTO jars(name, admin) VALUES($1, $2) returning id;",
			payload.Name,
			uid,
		).Scan(&jid)

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			_ = tx.Rollback()
			return
		}

		_, err = db.Query(
			"INSERT INTO jar_users(jar_id, user_id) VALUES($1, $2)",
			jid,
			uid,
		)

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			_ = tx.Rollback()
			return
		}

		err = tx.Commit()

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
			return
		}

		ctx.JSON(http.StatusCreated, gin.H{"id": jid})
		return
	}
}

func GetJar(db *sql.DB) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		id := ctx.Param("id")

		if id == "" {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "missing id in url"})
			return
		}

		jid, err := strconv.Atoi(id)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "id should be of type number"})
			return
		}

		var uid string
		err = db.QueryRow("select id from users where email=$1", ctx.GetHeader("principal")).Scan(&uid)

		var juId int
		row := db.QueryRow("select id from jar_users where user_id=$1 and jar_id=$2", uid, jid)
		err = row.Scan(&juId)

		if err != nil {
			ctx.Writer.WriteHeader(http.StatusForbidden)
			return
		}

		jar := struct {
			Id     int    `json:"id"`
			Name   string `json:"name"`
			Amount int    `json:"amount"`
		}{}

		err = db.QueryRow(
			"select id, name, amount from jars where id=$1",
			jid,
		).Scan(&jar.Id, &jar.Name, &jar.Amount)

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, jar)
		return
	}
}

func GetAllJars(db *sql.DB) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		var uid string
		err := db.QueryRow("select id from users where email=$1", ctx.GetHeader("principal")).Scan(&uid)

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var jIds []string
		rows, err := db.Query("select jar_id from jar_users where user_id=$1", uid)

		if rows == nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
			return
		}

		defer rows.Close()
		for rows.Next() {
			var jId int
			err = rows.Scan(&jId)

			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			jIds = append(jIds, strconv.Itoa(jId))
		}

		var jars []struct {
			Id     int    `json:"id"`
			Name   string `json:"name"`
			Admin  int    `json:"admin"`
			Amount int    `json:"amount"`
		}

		if len(jIds) > 0 {
			jarRows, err := db.Query(
				fmt.Sprintf(
					"select id, name, admin, amount from jars where id in (%s)",
					strings.Join(jIds, ","),
				),
			)

			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			defer jarRows.Close()
			for jarRows.Next() {
				jar := struct {
					Id     int    `json:"id"`
					Name   string `json:"name"`
					Admin  int    `json:"admin"`
					Amount int    `json:"amount"`
				}{}

				err = jarRows.Scan(&jar.Id, &jar.Name, &jar.Admin, &jar.Amount)

				if err != nil {
					ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}

				jars = append(jars, jar)
			}

			ctx.JSON(http.StatusOK, gin.H{"jars": jars})
			return
		} else {
			ctx.JSON(http.StatusOK, gin.H{"jars": []struct{}{}})
			return
		}

	}
}

func GetAllUsersWithSearch(db *sql.DB) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		search := ctx.Query("search")

		if len(search) < 3 {
			ctx.JSON(http.StatusPreconditionFailed, gin.H{"error": "search query param must have at least 3 characters"})
			return
		}

		rows, err := db.Query("select id, name, email from users where email like '%' || $1 || '%'", search)

		if rows == nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
			return
		}

		var users []struct {
			Id    int    `json:"id"`
			Name  string `json:"name"`
			Email string `json:"email"`
		}

		defer rows.Close()

		for rows.Next() {
			user := struct {
				Id    int    `json:"id"`
				Name  string `json:"name"`
				Email string `json:"email"`
			}{}
			err = rows.Scan(&user.Id, &user.Name, &user.Email)

			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			users = append(users, user)
		}

		if len(users) == 0 {
			ctx.JSON(http.StatusOK, gin.H{"users": []struct{}{}})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"users": users})
		return
	}
}

func InviteUser(db *sql.DB) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		id := ctx.Param("id")

		if id == "" {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "missing id in url"})
			return
		}

		b, err := ioutil.ReadAll(ctx.Request.Body)
		defer ctx.Request.Body.Close()

		payload := struct {
			UserId int `json:"userId"`
		}{}
		err = json.Unmarshal(b, &payload)

		if err != nil {
			ctx.JSON(http.StatusPreconditionFailed, gin.H{"error": "user id is missing in request"})
			return
		}

		jid, err := strconv.Atoi(id)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "id should be of type number"})
			return
		}

		var uid int
		err = db.QueryRow("select id from users where email=$1", ctx.GetHeader("principal")).Scan(&uid)

		if uid == payload.UserId {
			ctx.JSON(http.StatusPreconditionFailed, gin.H{"error": "user can not invite herself"})
			return
		}

		var juId int
		row := db.QueryRow("select id from jar_users where user_id=$1 and jar_id=$2", uid, jid)
		err = row.Scan(&juId)

		if err != nil {
			ctx.Writer.WriteHeader(http.StatusForbidden)
			return
		}

		var invitedId string
		err = db.QueryRow("select id from users where id=$1", payload.UserId).Scan(&invitedId)

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "no user with given userId"})
			return
		}

		var relId int
		err = db.QueryRow(
			"insert into jar_users(jar_id, user_id) values($1, $2) returning id",
			jid,
			invitedId,
		).Scan(&relId)

		if err != nil {
			ctx.JSON(http.StatusPreconditionFailed, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusCreated, gin.H{"relationId": relId})
	}
}

func main() {
	var dbUrl string
	if os.Getenv("DATABASE_URL") == "" {
		dbUrl = "postgres://postgres:postgres@localhost:5434/postgres?sslmode=disable"
	} else {
		dbUrl = os.Getenv("DATABASE_URL")
	}

	var port string
	if os.Getenv("PORT") == "" {
		port = "8000"
	} else {
		port = os.Getenv("PORT")
	}

	db, _ := sql.Open("postgres", dbUrl)

	router := gin.Default()

	router.LoadHTMLGlob("static/*.html")
	router.Static("assets", "./static")

	auth := router.Group("/auth")
	{
		auth.POST("/register", Register(db))
		auth.POST("/sign-in", SignIn(db))
		auth.POST("/logout")
	}

	api := router.Group("/api").Use(Authenticate())
	{
		api.POST("/jars", CreateJar(db))             // create jar
		api.GET("/jars", GetAllJars(db))             // get all jars
		api.GET("/jars/:id", GetJar(db))             // get one jar
		api.PUT("/jars/:id")                         // update one jar
		api.DELETE("/jars/:id")                      // delete one jar
		api.PATCH("/jars/:id")                       // update jar's fine
		api.POST("/jars/:id/fine/:id")               // fine user
		api.POST("/jars/:id/invite", InviteUser(db)) // invite user(s) to jar
		api.GET("/users", GetAllUsersWithSearch(db)) // get all users
		api.POST("/users/:id")                       // pay specific fine per user
	}

	router.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	log.Fatal(router.Run(":" + port))
}
