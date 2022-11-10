package utils

import (
	// "context"
	// "fmt"
	"context"
	"errors"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/vitostamatti/jwt-auth/database"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	// "go.mongodb.org/mongo-driver/mongo/options"
)

type SignedDetails struct {
	Email     string
	FirstName string
	LastName  string
	UserType  string
	UserId    string
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var SECRET_KEY string = os.Getenv("SECRET_KEY")

func GenerateTokens(email string, firstName string, lastName string, userType string, userId string) (token string, refreshToken string, err error) {
	claims := &SignedDetails{
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		UserId:    userId,
		UserType:  userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	refreshClaims := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24*7)).Unix(),
		},
	}

	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return
	}
	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return
	}

	return token, refreshToken, err
}

func UpdateTokens(token string, refreshToken string, userId string) {
	var ctx, cancel = context.WithTimeout(context.Background(), time.Second*100)
	var updatedObj primitive.D
	defer cancel()

	updatedObj = append(updatedObj, bson.E{Key: "token", Value: token})
	updatedObj = append(updatedObj, bson.E{Key: "refresh_token", Value: refreshToken})

	UpdatedAt, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updatedObj = append(updatedObj, bson.E{Key: "updated_at", Value: UpdatedAt})

	upsert := true
	filter := bson.M{"user_id": userId}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}
	_, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updatedObj},
		},
		&opt,
	)

	if err != nil {
		log.Panic(err)
		return
	}
}

func ValidateToken(incomingToken string) (claims *SignedDetails, err error) {
	token, err := jwt.ParseWithClaims(
		incomingToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)

	if err != nil {
		return &SignedDetails{}, err
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		err = errors.New("incorrect token")
		return &SignedDetails{}, err
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {
		err = errors.New("token expired")
		return &SignedDetails{}, err
	}

	return claims, err
}
