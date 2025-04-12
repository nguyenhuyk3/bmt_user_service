package injectors

import (
	"user_service/db/sqlc"
	"user_service/internal/injectors/provider"
	messagebroker "user_service/internal/message_broker"
	"user_service/utils/redis"
	"user_service/utils/token/jwt"

	"github.com/google/wire"
)

var dbSet = wire.NewSet(
	provider.ProvidePgxPool,
	sqlc.NewStore,
)

var jwtSet = wire.NewSet(
	provider.ProvideSecretKey,
	jwt.NewJWTMaker,
)

var redisSet = wire.NewSet(
	redis.NewRedisClient,
)

var kafkaSet = wire.NewSet(
	messagebroker.NewKafkaMessageBroker,
)
