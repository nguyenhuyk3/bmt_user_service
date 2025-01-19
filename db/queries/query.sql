-- name: CheckAccountExistsByEmail :one
SELECT EXISTS(
    SELECT 1 FROM accounts WHERE email = $1
) AS exists;

-- name: InsertAccount :exec
INSERT INTO "accounts" ("email", "password", "role")
VALUES ($1, $2, $3);

-- name: InsertUserInfo :exec
INSERT INTO "user_infos" ("account_email", "name", "sex", "birth_day")
VALUES ($1, $2, $3, $4);


-- name: InsertUserAction :exec
INSERT INTO "user_actions" ("account_email", "created_at", "updated_at", "login_at", "logout_at")
VALUES ($1, NOW(), NOW(), NULL, NULL);