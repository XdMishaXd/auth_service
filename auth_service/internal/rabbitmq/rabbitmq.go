package rabbitmq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth_service/internal/models"

	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	dlxExchangeName = "email.dlx"
	dlqName         = "email.verification.dlq"
)

type RabbitMQClient struct {
	conn    *amqp.Connection
	channel *amqp.Channel
	queue   amqp.Queue
}

func New(urlForConn string, queueName string) (*RabbitMQClient, error) {
	const op = "rabbimq.New"

	conn, err := amqp.Dial(urlForConn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if err := declareDeadLetterInfra(ch, queueName, dlxExchangeName, dlqName); err != nil {
		ch.Close()
		conn.Close()
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	q, err := ch.QueueDeclare(
		queueName,
		true,  // durable
		false, // autoDelete
		false, // exclusive
		false, // noWait
		amqp.Table{
			"x-dead-letter-exchange": dlxExchangeName,
		},
	)
	if err != nil {
		ch.Close()
		conn.Close()
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &RabbitMQClient{conn: conn, channel: ch, queue: q}, nil
}

func (r *RabbitMQClient) SendMessage(ctx context.Context, msg models.Message) error {
	const op = "rabbimq.SendMessage"

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return r.channel.PublishWithContext(
		ctx,
		"",
		r.queue.Name,
		false,
		false,
		amqp.Publishing{
			ContentType:  "application/json",
			Body:         body,
			DeliveryMode: amqp.Persistent,
			Timestamp:    time.Now(),
		},
	)
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

// declareDeadLetterInfra объявляет DLX-exchange и DLQ, куда попадают
// сообщения, которые consumer явно nack'нул без requeue.
func declareDeadLetterInfra(ch *amqp.Channel, mainQueueName, dlxName, dlqName string) error {
	const op = "rabbimq.declareDeadLetterInfra"

	if err := ch.ExchangeDeclare(
		dlxName, // используем параметр, а не глобальную константу
		"direct",
		true, false, false, false,
		nil,
	); err != nil {
		return fmt.Errorf("%s: exchange declare: %w", op, err)
	}

	if _, err := ch.QueueDeclare(
		dlqName,
		true, false, false, false, nil,
	); err != nil {
		return fmt.Errorf("%s: queue declare: %w", op, err)
	}

	if err := ch.QueueBind(dlqName, mainQueueName, dlxName, false, nil); err != nil {
		return fmt.Errorf("%s: queue bind: %w", op, err)
	}

	return nil
}
