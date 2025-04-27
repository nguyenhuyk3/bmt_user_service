package writers

import (
	"user_service/global"

	"github.com/segmentio/kafka-go"
)

var (
	brokerAddresses []string
)

func (k *KafkaWriter) getAvailableBroker() string {
	for _, broker := range brokerAddresses {
		conn, err := kafka.Dial("tcp", broker)
		if err == nil {
			conn.Close()

			return broker
		}
	}

	// log.Fatal("no available Kafka broker")
	global.Logger.Info("no available Kafka broker")

	return ""
}

// Check if a topic already exists on the Kafka broker, and if not, automatically create it
func (k *KafkaWriter) ensureTopicExists(topic string) error {
	// Connect to Kafka broker
	conn, err := kafka.Dial("tcp", k.getAvailableBroker())
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
		NumPartitions:     3,
		ReplicationFactor: 1,
		ConfigEntries:     []kafka.ConfigEntry{},
	})
}
