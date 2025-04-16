package services

import "context"

//go:generate mockgen -source=message_broker.go -destination=../mocks/message_broker.mock.go -package=mocks

type IMessageBroker interface {
	SendMessage(ctx context.Context, topic, key string, message interface{}) error
	Close()
}
