package writers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
	"user_service/global"
	"user_service/internal/services"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

type KafkaWriter struct {
	Writer  *kafka.Writer
	CloseCh chan struct{}
}

// Close implements services.IMessageBrokerWriter.
func (k *KafkaWriter) Close() {
	if k.Writer != nil {
		k.Writer.Close()

		log.Println("kafka producer closed")
	}

	close(k.CloseCh)
}

// SendMessage implements services.IMessageBrokerWriter.
func (k *KafkaWriter) SendMessage(ctx context.Context, topic string, key string, message interface{}) error {
	if err := k.ensureTopicExists(topic); err != nil {
		global.Logger.Error("failed to ensure topic exists", zap.Any("err", err))
		return err
	}

	msgBytes, err := json.Marshal(message)
	if err != nil {
		return err
	}

	err = k.Writer.WriteMessages(ctx, kafka.Message{
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

func NewKafkaWriter() services.IMessageBrokerWriter {
	brokerAddresses = []string{
		global.Config.ServiceSetting.KafkaSetting.KafkaBroker_1,
		global.Config.ServiceSetting.KafkaSetting.KafkaBroker_2,
		global.Config.ServiceSetting.KafkaSetting.KafkaBroker_3,
	}

	validBrokers := []string{}
	for _, addr := range brokerAddresses {
		if addr != "" {
			validBrokers = append(validBrokers, addr)
		}
	}

	brokerAddresses = validBrokers
	if len(brokerAddresses) == 0 {
		// Exit if no broker is valid
		log.Fatal("KAFKA FATAL: No valid broker addresses configured. Check ServiceSetting.KafkaSetting in config")
	}

	writer := &kafka.Writer{
		Addr:     kafka.TCP(brokerAddresses...),
		Balancer: &kafka.LeastBytes{},
		// Reduce wait times for faster batch submissions
		BatchTimeout: 1000 * time.Millisecond,
		MaxAttempts:  3,
		BatchSize:    100,
		WriteTimeout: 5 * time.Second,
	}

	global.Logger.Info("kafka producer initialized")

	return &KafkaWriter{
		Writer:  writer,
		CloseCh: make(chan struct{}),
	}
}
