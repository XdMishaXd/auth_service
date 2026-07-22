package storage

import "errors"

var (
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")

	ErrAppNotFound = errors.New("app not found")

	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenConflict = errors.New("refresh token has already been rotated")

	ErrResetTokenNotFound = errors.New("reset token not found")
	ErrResetTokenUsed     = errors.New("reset token already used")

	ErrOAuthAccountNotFound       = errors.New("oauth account not found")
	ErrOAuthAccountAlreadyLinked  = errors.New("oauth account already linked to another user")
	ErrOAuthProviderAlreadyLinked = errors.New("user already has this provider linked")
	ErrOAuthStateNotFound         = errors.New("oauth state not found or expired")
	ErrOAuthLastAuthMethod        = errors.New("cannot unlink last authentication method")

	ErrMagicLinkNotFound      = errors.New("magic link not found")
	ErrPendingSessionNotFound = errors.New("pending session not found or expired")

	ErrUserAlreadyDeleted = errors.New("user already deleted")
)

// gcraScript реализует GCRA (Generic Cell Rate Algorithm) одним атомарным
// вызовом EVALSHA — исключает race между read-modify-write, которая была бы
// при отдельных INCR+EXPIRE командах.
//
// KEYS[1] - ключ лимита
// ARGV[1] - burst (максимум токенов в бакете)
// ARGV[2] - rate (токенов в секунду, как float string "0.0833" для 5/min)
// ARGV[3] - cost (сколько токенов стоит текущий запрос, обычно 1)
// ARGV[4] - now unix milliseconds
//
// Возвращает: {allowed (0/1), retry_after_ms, remaining}
const (
	GCRAScript = `
		local key = KEYS[1]
		local burst = tonumber(ARGV[1])
		local rate = tonumber(ARGV[2])
		local cost = tonumber(ARGV[3])
		local now = tonumber(ARGV[4])

		local emission_interval = 1000 / rate
		local increment = emission_interval * cost
		local burst_offset = emission_interval * burst

		local tat = tonumber(redis.call('GET', key))
		if tat == nil then
			tat = now
		end
		if tat < now then
			tat = now
		end

		local new_tat = tat + increment
		local allow_at = new_tat - burst_offset

		if allow_at > now then
			local retry_after = allow_at - now
			return {0, math.floor(retry_after), 0}
		end

		local ttl = math.ceil((new_tat - now) / 1000) + 1
		redis.call('SET', key, new_tat, 'PX', math.floor(burst_offset + increment) + 1000)

		local remaining = math.floor((burst_offset - (new_tat - now)) / emission_interval)
		if remaining < 0 then
			remaining = 0
		end

		return {1, 0, remaining}
	`
)
