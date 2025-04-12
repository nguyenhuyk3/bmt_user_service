package services

//go:generate mockgen -source=message_broker.go -destination=../mocks/message_broker.mock.go -package=mocks

type IMessageBroker interface {
	SendMessage(topic, key string, message interface{}) error
	Close()
}
