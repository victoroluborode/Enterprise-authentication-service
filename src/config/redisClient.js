const Redis = require('ioredis');
require('dotenv').config();

const redisOptions = {
  host: process.env.REDIS_HOST,
  port: parseInt(process.env.REDIS_PORT || "6379", 10),
  password: process.env.REDIS_PASSWORD || undefined,
  db: parseInt(process.env.REDIS_DB || "0", 10),
  maxRetriesPerRequest: null,
  enableOfflineQueue: true,
};

const redis = new Redis(redisOptions);

redis.on('connect', () => {
    console.log('Connected to Redis!');
});

redis.on('error', (err) => {
    console.error('Redis connection error:', err);
});

module.exports = redis;