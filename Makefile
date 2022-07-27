docker-psql:
	docker-compose exec postgres psql -U btokens

docker-dev:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass /bin/bash

docker-test:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass go test ./...

docker:
	docker build -t brave/challenge-bypass:$$(git rev-parse --short HEAD) .
	docker tag brave/challenge-bypass:$$(git rev-parse --short HEAD) brave/challenge-bypass:latest

docker-release:
	docker push brave/challenge-bypass:$$(git rev-parse --short HEAD)
	docker push brave/challenge-bypass:latest

generate-avro:
	rm ./avro/generated/*
	gogen-avro --containers=true --package=generated ./avro/generated ./avro/schemas/*
	sed -i 's/Public_key/Issuer_public_key/g' ./avro/generated/signing_result*.go
	sed -i 's/"public_key/"issuer_public_key/g' ./avro/generated/signing_result*.go

lint:
	docker run --rm -v "$$(pwd):/app" --workdir /app golangci/golangci-lint:v1.46.2 go get ./... && golangci-lint run -v ./...
