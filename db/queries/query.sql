-- name: CheckAccountExistsByEmail :one
SELECT EXISTS(
    SELECT 1 FROM accounts WHERE email = $1
) AS exists;

-- name: InsertAccount :exec
INSERT INTO "accounts" ("email", "password", "role")
VALUES ($1, $2, $3);

-- name: InsertUserInfo :exec
INSERT INTO "user_infos" ("email", "name", "sex", "birth_day")
VALUES ($1, $2, $3, $4);


-- name: InsertUserAction :exec
INSERT INTO "user_actions" ("email", "created_at", "updated_at", "login_at", "logout_at")
VALUES ($1, NOW(), NOW(), NULL, NULL);

-- name: GetUserByEmail :one
SELECT *
FROM accounts
WHERE email = $1;

-- name: UpdateAction :execresult
UPDATE "user_actions"
SET 
    login_at = CASE WHEN $1::timestamptz IS NOT NULL THEN $1::timestamptz ELSE login_at END,
    logout_at = CASE WHEN $2::timestamptz IS NOT NULL THEN $2::timestamptz ELSE logout_at END,
    updated_at = now()
WHERE email = $3::text
RETURNING 
    login_at AS login_at,
    logout_at AS logout_at,
    email AS email;