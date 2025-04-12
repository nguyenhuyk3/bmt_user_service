package services

//go:generate mockgen -source=message_broker.go -destination=../internal/mocks/message_broker_mock.go -package=mocks

type IMessageBroker interface {
	SendMessage(topic, key string, message interface{}) error
	Close()
}
