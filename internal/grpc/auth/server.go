package auth

import (
	"context"
	"fmt"
	"reflect"

	ssov1 "github.com/SmoothWay/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(ctx context.Context, email string, password string, appId int) (token string, err error)
	RegisterNewUser(ctx context.Context, email string, password string) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if err := validateFields(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// if req.GetEmail() == "" {
	// 	return nil, status.Error(codes.InvalidArgument, "email is required")
	// }

	// if req.GetPassword() == "" {
	// 	return nil, status.Error(codes.InvalidArgument, "password is required")
	// }

	// if req.GetAppId() == 0 {
	// 	return nil, status.Error(codes.InvalidArgument, "app_id is required")
	// }

	token, err := s.auth.Login(ctx, req.Email, req.Password, int(req.AppId))
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if err := validateFields(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	userID, err := s.auth.RegisterNewUser(ctx, req.Email, req.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.RegisterResponse{
		UserId: userID,
	}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if err := validateFields(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.UserId)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func validateFields(req any) error {
	t := reflect.ValueOf(req)
	if t.Kind() != reflect.Struct {
		return fmt.Errorf("invalid request type")
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		if isZeroValue(field) {
			return fmt.Errorf("%s is required", field.Type().Name())
		}
	}
	return nil
}

func isZeroValue(field reflect.Value) bool {
	switch field.Kind() {
	case reflect.Ptr, reflect.Interface:
		return field.IsNil()
	default:
		return reflect.DeepEqual(field.Interface(), reflect.Zero(field.Type()).Interface())
	}
}
