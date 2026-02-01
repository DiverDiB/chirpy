-- name: GetChirp :one
SELECT * FROM chirps
WHERE id = $1;