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
			Addr: kafka.TCP(global.Config.ServiceSetting.KafkaSetting.KafkaBroker_1,
				global.Config.ServiceSetting.KafkaSetting.KafkaBroker_2,
				global.Config.ServiceSetting.KafkaSetting.KafkaBroker_3),
			Balancer: &kafka.LeastBytes{},
			// Reduce wait times for faster batch submissions
			BatchTimeout: 500 * time.Millisecond,
		}
		// log.Println("kafka producer initialized")
	})
}

// Check if a topic already exists on the Kafka broker, and if not, automatically create it
func ensureTopicExists(topic string) error {
	// Connect to Kafka broker
	conn, err := kafka.Dial("tcp", global.Config.ServiceSetting.KafkaSetting.KafkaBroker_1)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Check for topic existence
	partitions, err := conn.ReadPartitions(topic)
	if err == nil && len(partitions) > 0 {
		// Topic is exists
		return nil
	}
	// Create topic with 1 partition and replication-factor = 1
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

	// log.Printf("message sent to Kafka topic %s", topic)
	return nil
}

func Close() {
	if writer != nil {
		writer.Close()
		log.Println("kafka producer closed")
	}

	close(closeCh)
}
