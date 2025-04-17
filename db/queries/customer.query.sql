-- name: GetInforByEmail :one
SELECT * 
FROM user_infos
WHERE email = $1;

-- name: UpdateInforByEmail :exec
UPDATE user_infos
SET 
    name = $2, 
    sex = $3,
    birth_day = $4
WHERE email = $1; 
