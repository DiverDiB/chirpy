-- name: DeleteChirp :exec
DELETE FROM chirps
WHERE id = $1;