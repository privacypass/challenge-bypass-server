docker-psql:
	docker-compose exec postgres psql -U btokens

docker-dev:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass /bin/bash

docker-test:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass go test -count 1 -v -p 1

docker:
	docker build -t brave/challenge-bypass:$$(git rev-parse --short HEAD) .
	docker tag brave/challenge-bypass:$$(git rev-parse --short HEAD) brave/challenge-bypass:latest

docker-release:
	docker push brave/challenge-bypass:$$(git rev-parse --short HEAD)
	docker push brave/challenge-bypass:latest

generate-avro:
	gogen-avro --package=generated ./avro/generated ./avro/schemas/*

lint:
	docker run --rm -v "$$(pwd):/app" --workdir /app golangci/golangci-lint:v1.46.2 go get ./... && golangci-lint run -v ./...