-- name: UpdateUser :one
UPDATE users
SET
    updated_at = $2,
    email = $3,
    hashed_password = $4
WHERE id = $1
RETURNING *;