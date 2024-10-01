-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, user_id, body) VALUES (
	gen_random_uuid(),
	now(),
	now(),
	$1,
	$2
	) RETURNING *;

-- name: GetAllChirpsInAscendingOrder :many
SELECT * FROM chirps ORDER BY created_at ASC;

-- name: GetChirpByID :one
SELECT * FROM chirps WHERE id = $1 LIMIT 1;

-- name: DeleteChirp :exec
DELETE FROM chirps WHERE id = $1;
