package rabbitmq

import (
	"context"
	"errors"
	"fmt"
	"time"

	"email_sender/internal/metrics"

	amqp "github.com/rabbitmq/amqp091-go"
)

type RabbitMQClient struct {
	conn    *amqp.Connection
	channel *amqp.Channel
	metrics *metrics.Metrics
}

func New(url string, m *metrics.Metrics) (*RabbitMQClient, error) {
	const op = "rabbitmq.New"

	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &RabbitMQClient{
		conn:    conn,
		channel: ch,
		metrics: m,
	}, nil
}

// handler теперь возвращает error — это единственный способ узнать,
// удалось ли обработать сообщение, и соответственно ack или nack его,
// плюс записать это в metrics.
func (r *RabbitMQClient) StartReading(ctx context.Context, queueName string, handler func([]byte) error) error {
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

			r.processMessage(msg, handler)
		}
	}
}

func (r *RabbitMQClient) processMessage(msg amqp.Delivery, handler func([]byte) error) {
	start := time.Now()

	var procErr error

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				procErr = fmt.Errorf("handler panicked: %v", rec)
			}
		}()
		procErr = handler(msg.Body)
	}()

	duration := time.Since(start).Seconds()
	r.metrics.MessageProcessingDuration.Observe(duration)

	if procErr != nil {
		r.metrics.MessagesFailedTotal.WithLabelValues(reasonLabel()).Inc()
		// requeue=false: не гоняем письмо по кругу бесконечно при постоянной
		// ошибке (невалидный email и т.п.) — это отдельный разговор про DLQ,
		// пока хотя бы не теряем сообщение молча и не крутим retry storm
		_ = msg.Nack(false, false)
		return
	}

	r.metrics.MessagesConsumedTotal.Inc()
	_ = msg.Ack(false)
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
