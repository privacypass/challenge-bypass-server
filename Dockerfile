FROM rustlang/rust@sha256:5af55c68b21232886d8d9bd35563b8a2ac0f71952369fb71346a51b331acd0d4 as rust_builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools
RUN git clone https://github.com/brave-intl/challenge-bypass-ristretto-ffi /src
WORKDIR /src
RUN git checkout 1.0.0-pre.1
RUN cargo build --target=x86_64-unknown-linux-musl --features nightly

FROM golang:1.13.1 as go_builder
RUN apt-get update && apt-get install -y postgresql-client
RUN go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
RUN mkdir /src
WORKDIR /src
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY --from=rust_builder /src/target/x86_64-unknown-linux-musl/debug/libchallenge_bypass_ristretto.a /usr/lib/
COPY . .
RUN go build --ldflags '-extldflags "-static"' -o challenge-bypass-server main.go
CMD ["/src/challenge-bypass-server"]

FROM alpine:3.6
COPY --from=go_builder /src/challenge-bypass-server /bin/
COPY migrations /src/migrations
EXPOSE 2416
ENV DATABASE_URL=
ENV DBCONFIG="{}"
ENV MAX_DB_CONNECTION=100
CMD ["/bin/challenge-bypass-server"]
