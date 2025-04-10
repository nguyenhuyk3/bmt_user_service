-- name: GetInforByEmail :one
SELECT * 
FROM user_infos
WHERE email = $1;
