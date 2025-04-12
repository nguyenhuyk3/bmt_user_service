package messagebroker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"user_service/global"
	"user_service/internal/services"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

type KafkaMessageBroker struct {
}

// SendMessage implements services.IMessageBroker.
func (k *KafkaMessageBroker) SendMessage(topic string, key string, message interface{}) error {
	if writer == nil {
		initKafkaWriter()
	}

	if err := ensureTopicExists(topic); err != nil {
		global.Logger.Error("failed to ensure topic exists", zap.Any("err", err))
		return err
	}

	msgBytes, err := json.Marshal(message)
	if err != nil {
		return err
	}

	err = writer.WriteMessages(context.Background(), kafka.Message{
		Topic: topic,
		Key:   []byte(key),
		Value: msgBytes,
	})

	if err != nil {
		global.Logger.Error("failed to send message to Kafka", zap.Any("err", err))
		return err
	}

	global.Logger.Error(fmt.Sprintf("message sent to Kafka topic %s", topic))

	return nil
}

// Close implements services.IMessageBroker.
func (k *KafkaMessageBroker) Close() {
	if writer != nil {
		writer.Close()
		log.Println("kafka producer closed")
	}

	close(closeCh)
}

func NewKafkaMessageBroker() services.IMessageBroker {
	return &KafkaMessageBroker{}
}
