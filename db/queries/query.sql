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
    login_at = CASE WHEN @login_at::timestamptz IS NOT NULL THEN @login_at::timestamptz ELSE login_at END,
    logout_at = CASE WHEN @logout_at::timestamptz IS NOT NULL THEN @logout_at::timestamptz ELSE logout_at END,
    updated_at = now()
WHERE email = @email::text;
