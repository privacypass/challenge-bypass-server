# To-Date Challenge Bypass Kafka Consumer Tuning

## Why Are We Still Tuning?

- FFI on Intel Xeon Platinim 8259CL @2.50GHz processes around 700 records per second in a single thread when processing entirely local data.
- In 4 days we observed 185 million records from the Kafka backlog processed as well as 250 million of regular traffic. That comes to about 1,250 per second across 700 processors, which is fewer than 2 per second per consumer on average while utilizing an average 6% of CPU.

## Starting Kafka Consumer Configuration

```
reader := kafka.NewReader(kafka.ReaderConfig{
	Brokers:        brokers,
	Dialer:         getDialer(logger),
	GroupTopics:    topics,
	GroupID:        groupId,
	StartOffset:    kafka.FirstOffset,
	Logger:         kafkaLogger,
	MaxWait:        time.Millisecond * 200, // default 10s
	CommitInterval: time.Second,      // flush commits to Kafka every second
	MinBytes:       1e6,              // 1MB
	MaxBytes:       4e6,              // 6MB
})
```

## Tuning Timeline and Results

- Initial configuration
  - Messages processed per second: ~9
  - Total consumer count: 10
  - Total partition count: 10
- [`c1034017cdc8dddfa0153fd36110fe61f88ca0b6`](https://github.com/brave-intl/challenge-bypass-server/commit/c1034017cdc8dddfa0153fd36110fe61f88ca0b6):
  - Increase MinBytes to 20MB
  - Increase MaxBytes to 30MB
  - Messages processed per second: ~68
  - Total consumer count: 100
  - Total partition count: 100
- [`0c25af091f82d26e2eacce75e7446562b7bf74b8`](https://github.com/brave-intl/challenge-bypass-server/commit/0c25af091f82d26e2eacce75e7446562b7bf74b8):
  - Decrease MinBytes to 1KB
  - Decrease MaxBytes to 4MB
  - Messages processed per second: ~68
  - Total consumer count: 10
  - Total partition count: 10
- [`e4532d0d6b727b378f44a5c67ed1f3f4b0602d5d`](https://github.com/brave-intl/challenge-bypass-server/commit/e4532d0d6b727b378f44a5c67ed1f3f4b0602d5d):
  - Increase MinBytes to 50MB
  - Increase MaxBytes to 100MB
  - Increase MaxWait to 20 seconds
  - Messages processed per second: ~96
  - Total consumer count: 10
  - Total partition count: 10
- [`d475a6cd3799f56e983a4aa8aa9e5001e08832d7`](https://github.com/brave-intl/challenge-bypass-server/commit/d475a6cd3799f56e983a4aa8aa9e5001e08832d7):
  - Decrease MinBytes to 1KB
  - Decrease MaxBytes to 10MB
  - Reuse Producer connections
  - Messages processed per second: ~95
  - Total consumer count: 10
  - Total partition count: 10
- [`7bb83610a279b9662e78d75186cddc7e21bb6a81`](https://github.com/brave-intl/challenge-bypass-server/commit/7bb83610a279b9662e78d75186cddc7e21bb6a81):
  - Allow containers to spawn multiple consumers based on environment variable
- Increase partition count to 700
  - Messages processed per second: ~483
  - Total consumer count: 700
  - Total partition count: 10
