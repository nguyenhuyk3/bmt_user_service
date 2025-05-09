// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: auth.query.sql

package sqlc

import (
	"context"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

const checkAccountExistsByEmailAndSource = `-- name: CheckAccountExistsByEmailAndSource :one
SELECT EXISTS(
    SELECT 1 FROM accounts WHERE email = $1 AND source = $2
) AS exists
`

type CheckAccountExistsByEmailAndSourceParams struct {
	Email  string      `json:"email"`
	Source NullSources `json:"source"`
}

func (q *Queries) CheckAccountExistsByEmailAndSource(ctx context.Context, arg CheckAccountExistsByEmailAndSourceParams) (bool, error) {
	row := q.db.QueryRow(ctx, checkAccountExistsByEmailAndSource, arg.Email, arg.Source)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT email, password, source, role
FROM accounts
WHERE email = $1
`

func (q *Queries) GetUserByEmail(ctx context.Context, email string) (Accounts, error) {
	row := q.db.QueryRow(ctx, getUserByEmail, email)
	var i Accounts
	err := row.Scan(
		&i.Email,
		&i.Password,
		&i.Source,
		&i.Role,
	)
	return i, err
}

const insertAccount = `-- name: InsertAccount :exec
INSERT INTO "accounts" ("email", "password", "source", "role")
VALUES ($1, $2, $3, $4)
`

type InsertAccountParams struct {
	Email    string      `json:"email"`
	Password string      `json:"password"`
	Source   NullSources `json:"source"`
	Role     NullRoles   `json:"role"`
}

func (q *Queries) InsertAccount(ctx context.Context, arg InsertAccountParams) error {
	_, err := q.db.Exec(ctx, insertAccount,
		arg.Email,
		arg.Password,
		arg.Source,
		arg.Role,
	)
	return err
}

const insertOAuth2Action = `-- name: InsertOAuth2Action :exec
INSERT INTO "user_actions" ("email", "created_at", "updated_at", "login_at", "logout_at")
VALUES ($1, NOW(), NOW(), NOW(), NULL)
`

func (q *Queries) InsertOAuth2Action(ctx context.Context, email pgtype.Text) error {
	_, err := q.db.Exec(ctx, insertOAuth2Action, email)
	return err
}

const insertUserAction = `-- name: InsertUserAction :exec
INSERT INTO "user_actions" ("email", "created_at", "updated_at", "login_at", "logout_at")
VALUES ($1, NOW(), NOW(), NULL, NULL)
`

func (q *Queries) InsertUserAction(ctx context.Context, email pgtype.Text) error {
	_, err := q.db.Exec(ctx, insertUserAction, email)
	return err
}

const insertUserInfo = `-- name: InsertUserInfo :exec
INSERT INTO "user_infos" ("email", "name", "sex", "birth_day")
VALUES ($1, $2, $3, $4)
`

type InsertUserInfoParams struct {
	Email    pgtype.Text `json:"email"`
	Name     string      `json:"name"`
	Sex      NullSex     `json:"sex"`
	BirthDay string      `json:"birth_day"`
}

func (q *Queries) InsertUserInfo(ctx context.Context, arg InsertUserInfoParams) error {
	_, err := q.db.Exec(ctx, insertUserInfo,
		arg.Email,
		arg.Name,
		arg.Sex,
		arg.BirthDay,
	)
	return err
}

const updatePassword = `-- name: UpdatePassword :exec
UPDATE "accounts"
SET 
    password = $1
WHERE email = $2
`

type UpdatePasswordParams struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

func (q *Queries) UpdatePassword(ctx context.Context, arg UpdatePasswordParams) error {
	_, err := q.db.Exec(ctx, updatePassword, arg.Password, arg.Email)
	return err
}

const updateUserAction = `-- name: UpdateUserAction :execresult
UPDATE "user_actions"
SET 
    login_at = CASE WHEN $1::timestamptz IS NOT NULL THEN $1::timestamptz ELSE login_at END,
    logout_at = CASE WHEN $2::timestamptz IS NOT NULL THEN $2::timestamptz ELSE logout_at END,
    updated_at = CASE WHEN $3::timestamptz IS NOT NULL THEN $3::timestamptz ELSE updated_at END
WHERE email = $4::text
`

type UpdateUserActionParams struct {
	LoginAt   pgtype.Timestamptz `json:"login_at"`
	LogoutAt  pgtype.Timestamptz `json:"logout_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
	Email     string             `json:"email"`
}

func (q *Queries) UpdateUserAction(ctx context.Context, arg UpdateUserActionParams) (pgconn.CommandTag, error) {
	return q.db.Exec(ctx, updateUserAction,
		arg.LoginAt,
		arg.LogoutAt,
		arg.UpdatedAt,
		arg.Email,
	)
}
