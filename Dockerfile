FROM golang:1.8

WORKDIR /go/src/github.com/brave-intl/challenge-bypass-server
COPY . .

RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
RUN dep ensure

RUN apt update
RUN apt install -y postgresql-client

EXPOSE ${PORT}

ENTRYPOINT ["go", "run", "main.go"]
