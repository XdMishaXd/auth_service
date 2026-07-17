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
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
SELECT cron.unschedule('cleanup_cron_job_run_details');
SELECT cron.unschedule('cleanup_expired_magic_links');
DROP EXTENSION IF EXISTS pg_cron;
-- +goose StatementEnd
