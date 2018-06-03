package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
)

const (
	contentType string = "Content-Type"
	jsonType    string = "application/json"
)

// Joke contains information about a single Joke
type Joke struct {
	ID    int    `json:"id" binding:"required"`
	Likes int    `json:"likes"`
	Joke  string `json:"joke" binding:"required"`
}

// List of jokes
var jokes = []Joke{
	Joke{1, 0, "Did you hear about the restaurant on the moon? Great food, no atmosphere."},
	Joke{2, 0, "What do you call a fake noodle? An Impasta."},
	Joke{3, 0, "How many apples grow on a tree? All of them."},
	Joke{4, 0, "Want to hear a joke about paper? Nevermind it's tearable."},
	Joke{5, 0, "I just watched a program about beavers. It was the best dam program I've ever seen."},
	Joke{6, 0, "Why did the coffee file a police report? It got mugged."},
	Joke{7, 0, "How does a penguin build it's house? Igloos it together."},
}

var jwtMiddleWare *jwtmiddleware.JWTMiddleware

// Jwks stores a slice of JSON Web Keys
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

// JSONWebKeys web keys
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

func main() {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			aud := os.Getenv("AUTHO_API_AUDIENCE")
			checkAudience := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
			if !checkAudience {
				return token, errors.New("Invalid audience")
			}
			// verify iss claim
			iss := os.Getenv("AUTH0_DOMAIN")
			fmt.Println("About to verify issuer", iss)
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
			if !checkIss {
				return token, errors.New("Invalid issuer")
			}

			cert, err := getPemCert(token)
			if err != nil {
				log.Fatalf("could not get cert: %+v", err)
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	})

	// register our actual jwtMiddleware
	jwtMiddleWare = jwtMiddleware

	// Set the router as the default one shipped with Gin
	router := gin.Default()
	// Serve frontend static files
	router.Use(static.Serve("/", static.LocalFile("./views", true)))
	// Setup route group for the API
	api := router.Group("/api")
	{
		api.GET("/", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "pong",
			})
		})
		api.GET("/jokes", authMiddleware(), JokeHandler)
		api.POST("/jokes/like/:jokeID", authMiddleware(), LikeJoke)

	}
	// Start and run the server
	router.Run(":3000")
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get(os.Getenv("AUTH0_DOMAIN") + ".well-known/jwks.json")
	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()
	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return cert, err
	}
	x5c := jwks.Keys[0].X5c
	for k, v := range x5c {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + v + "\n-----END CERTIFICATE-----"
		}
	}
	if cert == "" {
		return cert, errors.New("unable to find appropriate key")
	}
	return cert, nil
}

// authMiddleware intercepts the requests, and check for a valid jwt token
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the client secret key
		err := jwtMiddleWare.CheckJWT(c.Writer, c.Request)
		if err != nil {
			// Token not found
			fmt.Println(err)
			c.Abort()
			c.Writer.WriteHeader(http.StatusUnauthorized)
			c.Writer.Write([]byte("Unauthorized"))
			return
		}
	}
}

// JokeHandler : retrieves a list of available jokes
func JokeHandler(c *gin.Context) {
	c.Header(contentType, jsonType)
	c.JSON(http.StatusOK, jokes)
}

// LikeJoke : increments the likes of a particular joke
func LikeJoke(c *gin.Context) {
	// Check joke ID is valid
	if jokeid, err := strconv.Atoi(c.Param("jokeID")); err == nil {
		// find joke and increment likes
		for i := 0; i < len(jokes); i++ {
			if jokes[i].ID == jokeid {
				jokes[i].Likes = jokes[i].Likes + 1
			}
		}
		c.JSON(http.StatusOK, &jokes)
	} else {
		// the jokes ID is invalid
		c.AbortWithStatus(http.StatusNotFound)
	}
}
