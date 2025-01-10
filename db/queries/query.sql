-- name: CheckAccountExistsByEmail :one
SELECT EXISTS(
    SELECT 1 FROM accounts WHERE email = $1
) AS exists;