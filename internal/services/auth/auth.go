package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/storage"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrinvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
)

type AuthService struct {
	log      *slog.Logger
	tokenTTL time.Duration
	UserSaver
	UserProvider
	AppProvider
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passhash []byte) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (user models.User, err error)
	IsAdmin(ctx context.Context, userID int64) (isAdmin bool, err error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (app models.App, err error)
}

func New(log *slog.Logger, tokenTTL time.Duration, userSaver UserSaver, userProvider UserProvider, appProvider AppProvider) *AuthService {
	return &AuthService{
		log:          log,
		tokenTTL:     tokenTTL,
		UserSaver:    userSaver,
		UserProvider: userProvider,
		AppProvider:  appProvider,
	}
}

func (a *AuthService) Login(ctx context.Context, email string, password string, appId int) (string, error) {
	const op = "auth.Login"

	log := a.log.With("op", op, slog.String("email", email))

	user, err := a.UserProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Error(err.Error())
			return "", fmt.Errorf("%s: %w", op, ErrinvalidCredentials)
		}

		log.Error("failed to get user", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password))
	if err != nil {
		log.Error("invalid creds", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, ErrinvalidCredentials)
	}

	app, err := a.AppProvider.App(ctx, appId)
	if err != nil {
		log.Error("failed to get app provider", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to make token", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return token, nil
}

func (a *AuthService) RegisterNewUser(ctx context.Context, email string, password string) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With("op", op, slog.String("email", email))

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", slog.String("error", err.Error()))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	userid, err := a.UserSaver.SaveUser(ctx, email, passwordHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Error("user already exists", slog.String("error", err.Error()))
			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}
		log.Error("failed to save user", slog.String("error", err.Error()))
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("user registered", slog.Int64("userId", userid))

	return userid, nil
}

func (a *AuthService) IsAdmin(ctx context.Context, userId int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With("op", op, slog.Int64("userId", userId))

	isAdmin, err := a.UserProvider.IsAdmin(ctx, userId)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.String("error", err.Error()))
			return false, fmt.Errorf("%s: %w", op, ErrinvalidCredentials)
		}
		log.Error("failed to get admin status", slog.String("error", err.Error()))
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked", slog.Bool("isAdmin", isAdmin))

	return isAdmin, nil
}
