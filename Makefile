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
	gogen-avro --containers=true --package=generated ./avro/generated ./avro/schemas/*
	echo "WARNING: The generated signing_result.go file has a property called Public_key which must be changed manually to Issuer_public_key in all instances. Its json representation must also be updated to be issuer_public_key. If this need is to be fixed it will require a schema update on the ads-serve side as well."

lint:
	docker run --rm -v "$$(pwd):/app" --workdir /app golangci/golangci-lint:v1.46.2 go get ./... && golangci-lint run -v ./...
