FROM rustlang/rust@sha256:ff3e6405319286ee5ff427ffdda577760507774f4c1dd7bab12ebc54ad31a696 as rust_builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools
RUN git clone https://github.com/brave-intl/challenge-bypass-ristretto-ffi /src
WORKDIR /src
RUN git checkout 1.0.0-pre.4
RUN cargo build --target=x86_64-unknown-linux-musl --features nightly

FROM golang:1.16 as go_builder
RUN apt-get update && apt-get install -y ca-certificates postgresql-client python3-pip
RUN pip install awscli --upgrade
RUN curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(go env GOPATH)/bin latest
RUN mkdir /src
WORKDIR /src
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY --from=rust_builder /src/target/x86_64-unknown-linux-musl/debug/libchallenge_bypass_ristretto_ffi.a /usr/lib/libchallenge_bypass_ristretto.a
COPY . .
RUN go build --ldflags '-extldflags "-static"' -o challenge-bypass-server main.go
CMD ["/src/challenge-bypass-server"]

FROM ubuntu
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y ca-certificates awscli && rm -rf /var/cache/apk/*
RUN update-ca-certificates
COPY --from=go_builder /src/challenge-bypass-server /bin/
COPY migrations /src/migrations
EXPOSE 2416
ENV DATABASE_URL=
ENV DBCONFIG="{}"
ENV MAX_DB_CONNECTION=100
ENV AWS_REGION="us-west-2"
ENV EXPIRATION_WINDOW=7
ENV RENEWAL_WINDOW=30
ENV DYNAMODB_ENDPOINT=
CMD ["/bin/challenge-bypass-server"]
