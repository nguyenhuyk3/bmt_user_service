package initializations

import (
	"context"
	"fmt"
	"log"
	"user_service/global"

	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

func initRedis() {
	r := global.Config.ServiceSetting.RedisSetting
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%v", r.Host, r.Port),
		Password: r.Password,
		DB:       r.Database,
		PoolSize: 10,
	})
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("redis initialization error: %v", err)
	}

	global.RDb = rdb
}
