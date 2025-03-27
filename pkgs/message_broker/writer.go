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
			// Reduce wait times for faster batch submissions
			BatchTimeout: 500 * time.Millisecond,
		}
		// log.Println("kafka producer initialized")
	})
}

// Hàm kiểm tra và tạo topic nếu chưa tồn tại
func ensureTopicExists(topic string) error {
	conn, err := kafka.Dial("tcp", global.Config.Server.KafkaBroker)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Kiểm tra danh sách topic
	partitions, err := conn.ReadPartitions(topic)
	if err == nil && len(partitions) > 0 {
		// Topic đã tồn tại
		return nil
	}

	// Tạo topic với 1 partition và replication-factor = 1
	return conn.CreateTopics(kafka.TopicConfig{
		Topic:             topic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	})
}

func SendMessage(topic string, key string, value interface{}) error {
	if writer == nil {
		initKafkaWriter()
	}

	if err := ensureTopicExists(topic); err != nil {
		log.Printf("failed to ensure topic exists: %v", err)
		return err
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
		log.Printf("failed to send message to Kafka: %v", err)
		return err
	}

	log.Printf("message sent to Kafka topic %s", topic)
	return nil
}

func Close() {
	if writer != nil {
		writer.Close()
		log.Println("kafka producer closed")
	}

	close(closeCh)
}
