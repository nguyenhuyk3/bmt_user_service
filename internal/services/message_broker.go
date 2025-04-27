package services

import "context"

//go:generate mockgen -source=message_broker.go -destination=../mocks/message_broker.mock.go -package=mocks

type IMessageBrokerWriter interface {
	SendMessage(ctx context.Context, topic, key string, message interface{}) error
	Close()
}
