package messagebroker

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"
	"user_service/global"

	"github.com/segmentio/kafka-go"
)

var (
	writer  *kafka.Writer
	once    sync.Once
	closeCh = make(chan struct{})
)

func initKafkaWriter() {
	once.Do(func() {
		writer = &kafka.Writer{
			Addr:     kafka.TCP(global.Config.Server.KafkaBroker),
			Balancer: &kafka.LeastBytes{},
			// Giảm thời gian chờ để gửi batch nhanh hơn
			BatchTimeout: 500 * time.Millisecond,
		}
		log.Println("Kafka producer initialized")
	})
}

func SendMessage(topic string, key string, value interface{}) error {
	if writer == nil {
		initKafkaWriter()
	}

	msgBytes, err := json.Marshal(value)
	if err != nil {
		return err
	}

	err = writer.WriteMessages(context.Background(), kafka.Message{
		Topic: topic,
		Key:   []byte(key),
		Value: msgBytes,
	})

	if err != nil {
		log.Printf("Failed to send message to Kafka: %v", err)
		return err
	}

	log.Printf("Message sent to Kafka topic %s", topic)
	return nil
}

func Close() {
	if writer != nil {
		writer.Close()
		log.Println("Kafka producer closed")
	}

	close(closeCh)
}
