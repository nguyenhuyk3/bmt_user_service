-- name: CheckAccountExistsByEmailAndSource :one
SELECT EXISTS(
    SELECT 1 FROM accounts WHERE email = $1 AND source = $2
) AS exists;

-- name: InsertAccount :exec
INSERT INTO "accounts" ("email", "password", "source", "role")
VALUES ($1, $2, $3, $4);

-- name: InsertUserInfo :exec
INSERT INTO "user_infos" ("email", "name", "sex", "birth_day")
VALUES ($1, $2, $3, $4);


-- name: InsertUserAction :exec
INSERT INTO "user_actions" ("email", "created_at", "updated_at", "login_at", "logout_at")
VALUES ($1, NOW(), NOW(), NULL, NULL);

-- name: InsertOAuth2Action :exec
INSERT INTO "user_actions" ("email", "created_at", "updated_at", "login_at", "logout_at")
VALUES ($1, NOW(), NOW(), NOW(), NULL);

-- name: GetUserByEmail :one
SELECT *
FROM accounts
WHERE email = $1;

-- name: UpdateUserAction :execresult
UPDATE "user_actions"
SET 
    login_at = CASE WHEN @login_at::timestamptz IS NOT NULL THEN @login_at::timestamptz ELSE login_at END,
    logout_at = CASE WHEN @logout_at::timestamptz IS NOT NULL THEN @logout_at::timestamptz ELSE logout_at END,
    updated_at = CASE WHEN @updated_at::timestamptz IS NOT NULL THEN @updated_at::timestamptz ELSE updated_at END
WHERE email = @email::text;

-- name: UpdatePassword :exec 
UPDATE "accounts"
SET 
    password = $1
WHERE email = $2;




