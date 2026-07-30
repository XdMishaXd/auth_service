package rabbitmq

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"email_sender/internal/metrics"

	amqp "github.com/rabbitmq/amqp091-go"
)

type RabbitMQClient struct {
	conn    *amqp.Connection
	channel *amqp.Channel
	metrics *metrics.Metrics
	log     *slog.Logger
}

func New(url string, m *metrics.Metrics, log *slog.Logger) (*RabbitMQClient, error) {
	const op = "rabbitmq.New"

	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	ch, err := conn.Channel()
	if err != nil {
		closeErr := conn.Close()
		return nil, fmt.Errorf("%s: %w", op, errors.Join(err, closeErr))
	}

	return &RabbitMQClient{
		conn:    conn,
		channel: ch,
		metrics: m,
		log:     log,
	}, nil
}

// handler теперь возвращает error — это единственный способ узнать,
// удалось ли обработать сообщение, и соответственно ack или nack его,
// плюс записать это в metrics.
func (r *RabbitMQClient) StartReading(ctx context.Context, queueName string, handler func(context.Context, []byte) error) error {
	const op = "rabbitmq.StartReading"

	msgs, err := r.channel.Consume(
		queueName, "", false, false, false, false, nil,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case msg, ok := <-msgs:
			if !ok {
				// канал закрылся НЕ из-за ctx.Done() — это авария
				// (разрыв соединения/канала с RabbitMQ), а не штатный shutdown
				return fmt.Errorf("%s: channel closed unexpectedly", op)
			}

			r.processMessage(ctx, msg, handler)
		}
	}
}

func (r *RabbitMQClient) processMessage(ctx context.Context, msg amqp.Delivery, handler func(context.Context, []byte) error) {
	start := time.Now()

	msgCtx, cancel := context.WithTimeout(ctx, 30*time.Second) // подобрать под реальный SLA
	defer cancel()

	var procErr error
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				if err, ok := rec.(error); ok {
					procErr = fmt.Errorf("handler panicked: %w", err)
				} else {
					procErr = fmt.Errorf("handler panicked: %v", rec)
				}
			}
		}()
		procErr = handler(msgCtx, msg.Body)
	}()

	r.metrics.MessageProcessingDuration.Observe(time.Since(start).Seconds())

	if procErr != nil {
		r.metrics.MessagesFailedTotal.WithLabelValues(reasonLabel()).Inc()
		r.log.Error("message processing failed",
			"error", procErr,
			"delivery_tag", msg.DeliveryTag,
			"redelivered", msg.Redelivered,
		)

		// requeue=false: DLQ настроен на стороне продюсера (x-dead-letter-exchange),
		// поэтому nack без requeue уводит сообщение в DLQ, а не теряет его.
		if err := msg.Nack(false, false); err != nil {
			r.log.Error("nack failed",
				"error", err, "delivery_tag", msg.DeliveryTag)
		}
		return
	}

	r.metrics.MessagesConsumedTotal.Inc()
	if err := msg.Ack(false); err != nil {
		r.log.Error("ack failed",
			"error", err, "delivery_tag", msg.DeliveryTag)
	}
}

func reasonLabel() string {
	// пока просто "processing_error" — если появятся различимые типы ошибок
	// (SMTP timeout vs невалидный адрес vs шаблон) — разнесём на конкретные reason
	return "processing_error"
}

func (r *RabbitMQClient) Close(ctx context.Context) error {
	done := make(chan error, 1)

	go func() {
		var errs []error
		if err := r.channel.Close(); err != nil {
			errs = append(errs, fmt.Errorf("channel close: %w", err))
		}
		if err := r.conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("conn close: %w", err))
		}
		done <- errors.Join(errs...)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("rabbitmq close timed out: %w", ctx.Err())
	}
}
