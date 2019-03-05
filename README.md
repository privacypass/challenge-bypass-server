# Blinded Tokens Microservice

This is a fork of the [Challenge Bypass Server](https://github.com/privacypass/challenge-bypass-server), that implements the HTTP REST interface, persistence in Postgresql, multiple issuers, etc.

It also uses [cgo bindings to a rust library to implement the cryptographic protocol](https://github.com/brave-intl/challenge-bypass-ristretto-ffi).

## Dependencies

Install Docker.

## Run/build using docker

```
docker-compose up
```

## Testing

```
make docker-test
```

## Deployment

For testing purposes this repo can be deployed to Heroku. The settings set in environment variables `DBCONFIG` and `DATABASE_URL` override other options.
