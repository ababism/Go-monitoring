package userrepo

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/juju/zaputil/zapctx"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/anonimpopov/hw4/internal/model"
	"github.com/anonimpopov/hw4/internal/repo"
	"github.com/anonimpopov/hw4/internal/service"
)

type userRepo struct {
	pgxPool *pgxpool.Pool
	logger  *zap.Logger
	trace   trace.Tracer
}

func (r *userRepo) conn(ctx context.Context) Conn {
	if tx, ok := ctx.Value(repo.CtxKeyTx).(pgx.Tx); ok {
		return tx
	}

	return r.pgxPool
}

func (r *userRepo) WithNewTx(ctx context.Context, f func(ctx context.Context) error) error {
	return r.pgxPool.BeginFunc(ctx, func(tx pgx.Tx) error {
		return f(context.WithValue(ctx, repo.CtxKeyTx, tx))
	})
}

func (r *userRepo) AddUser(ctx context.Context, login, password, email string) error {
	newCtx, span := r.trace.Start(ctx, "repo: AddUser")
	defer span.End()
	ctx = zapctx.WithLogger(newCtx, r.logger)

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		r.logger.Error("Internal: can't generate hash", zap.Error(err))
		return err
	}

	_, err = r.conn(ctx).Exec(ctx, `INSERT INTO users (login, password_hash, email) VALUES ($1, $2, $3)`, login, hash, email)
	if err != nil {
		r.logger.Error("Internal: can't create user", zap.Error(err))
		return err
	}

	return nil
}

func (r *userRepo) GetUser(ctx context.Context, login string) (*model.User, error) {
	newCtx, span := r.trace.Start(ctx, "repo: getUser")
	defer span.End()
	ctx = zapctx.WithLogger(newCtx, r.logger)

	var user model.User

	row := r.conn(ctx).QueryRow(ctx, `SELECT login, password_hash, email FROM users WHERE login = $1`, login)
	if err := row.Scan(&user.Login, &user.HashedPassword, &user.Email); err != nil {
		if err == sql.ErrNoRows {
			return nil, service.ErrNotFound
		}
		r.logger.Error("Internal: can't get user", zap.Error(err))
		return nil, err
	}

	return &user, nil
}

func (r *userRepo) ValidateUser(ctx context.Context, login, password string) (*model.User, error) {
	newCtx, span := r.trace.Start(ctx, "repo: validateUser")
	defer span.End()
	ctx = zapctx.WithLogger(newCtx, r.logger)

	user, err := r.GetUser(ctx, login)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password)); err != nil {
		return nil, service.ErrForbidden
	}

	return user, nil
}

func New(config *service.AuthConfig, pgxPool *pgxpool.Pool, logging *zap.Logger, tracer trace.Tracer) (repo.User, error) {
	r := &userRepo{
		pgxPool: pgxPool,
		logger:  logging,
		trace:   tracer,
	}

	ctx := context.Background()

	err := r.pgxPool.BeginFunc(ctx, func(tx pgx.Tx) error {
		for _, user := range config.Users {
			if err := r.AddUser(ctx, user.Login, user.Pasword, user.Email); err != nil {
				r.logger.Fatal(err.Error())
			}
		}

		return nil
	})

	if err != nil {
		r.logger.Error("Internal: can't begin migrate func", zap.Error(err))
		return nil, err
	}

	return r, nil
}
