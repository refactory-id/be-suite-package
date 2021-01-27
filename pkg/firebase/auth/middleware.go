package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"github.com/joho/godotenv"
	"google.golang.org/api/option"
)

func AuthFirebaseMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		bearerToken := tokenFromHeader(r)
		if bearerToken == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		authClient := initAuthClient()
		token, err := authClient.VerifyIDToken(ctx, bearerToken)
		if err != nil {
			if strings.Contains(err.Error(), "expired") {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx = context.WithValue(ctx, userContextKey, User{
			UserID:      token.UID,
			Email:       token.Claims["email"].(string),
			DisplayName: token.Claims["name"].(string),
		})

		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func initAuthClient() *auth.Client {
	if en := godotenv.Load(); en != nil {
		fmt.Print(en)
	}

	var opts []option.ClientOption
	if file := os.Getenv("SERVICE_ACCOUNT_FILE"); file != "" {
		opts = append(opts, option.WithCredentialsFile(file))
	}

	config := &firebase.Config{ServiceAccountID: os.Getenv("SERVICE_ACCOUNT_ID")}
	firebaseApp, err := firebase.NewApp(context.Background(), config, opts...)
	if err != nil {
		log.Fatalf("Unable to initialize config firebase : %s", err.Error())
	}

	authClient, err := firebaseApp.Auth(context.Background())
	if err != nil {
		log.Fatalf("Unable to create firebase Auth client : %s", err.Error())
	}

	return authClient
}

func tokenFromHeader(r *http.Request) string {
	headerValue := r.Header.Get("Authorization")

	if len(headerValue) > 7 && strings.ToLower(headerValue[0:6]) == "bearer" {
		return headerValue[7:]
	}

	return ""
}

type User struct {
	UserID      string
	Email       string
	Role        string
	DisplayName string
}

type ctxKey int

const (
	userContextKey ctxKey = iota
)

func GetUserInfo(ctx context.Context) (User, error) {
	user, ok := ctx.Value(userContextKey).(User)
	if ok {
		return user, nil
	}

	return User{}, errors.New("User not found")
}
