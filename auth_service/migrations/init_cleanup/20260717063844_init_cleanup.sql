-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pg_cron;
-- Очистка истёкших magic-link токенов — раз в час, записи с expires_at
-- старше суток (см. cleanup_expired_magic_links()).
SELECT cron.schedule(
		'cleanup_expired_magic_links',
		'0 * * * *',
		$$SELECT cleanup_expired_magic_links() $$
	);
-- Очистка собственной истории запусков pg_cron — иначе cron.job_run_details
-- растёт неограниченно (по записи на каждый запуск каждого job).
SELECT cron.schedule(
		'cleanup_cron_job_run_details',
		'0 3 * * *',
		-- раз в сутки, в 3:00 UTC (pg_cron всегда интерпретирует расписание в GMT)
		$$DELETE
		FROM cron.job_run_details
		WHERE end_time < now() - interval '7 days' $$
	);
-- Полное (hard) удаление аккаунтов после истечения grace period (7 суток
-- с момента soft-delete, см. deleted_at на users). oauth_accounts,
-- refresh_tokens, password_reset_tokens, magic_links удаляются каскадом
-- через существующие ON DELETE CASCADE.
CREATE OR REPLACE FUNCTION hard_delete_expired_accounts() RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE total_deleted INTEGER := 0;
batch_deleted INTEGER;
BEGIN LOOP
DELETE FROM users
WHERE id IN (
		SELECT id
		FROM users
		WHERE deleted_at IS NOT NULL
			AND deleted_at < NOW() - INTERVAL '7 days'
		ORDER BY id
		LIMIT 100 FOR
		UPDATE SKIP LOCKED
	);
GET DIAGNOSTICS batch_deleted = ROW_COUNT;
total_deleted := total_deleted + batch_deleted;
EXIT
WHEN batch_deleted < 100;
END LOOP;
RETURN total_deleted;
END;
$$;
SELECT cron.schedule(
		'hard_delete_expired_accounts',
		'0 * * * *',
		$$SELECT hard_delete_expired_accounts() $$
	);
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
SELECT cron.unschedule('hard_delete_expired_accounts');
DROP FUNCTION IF EXISTS hard_delete_expired_accounts();
SELECT cron.unschedule('cleanup_cron_job_run_details');
SELECT cron.unschedule('cleanup_expired_magic_links');
DROP EXTENSION IF EXISTS pg_cron;
-- +goose StatementEnd
