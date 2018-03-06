FROM golang:1.9-alpine as builder

RUN apk add --no-cache git build-base curl
RUN curl -L -k -s https://github.com/golang/dep/releases/download/v0.4.1/dep-linux-amd64 -o $GOPATH/bin/dep \
    && chmod +x $GOPATH/bin/dep

WORKDIR /go/src/github.com/ory/hydra-consent-app-go

ADD . .

RUN dep ensure -vendor-only

RUN go build -o consentapp

FROM alpine:3.7

COPY --from=builder /go/src/github.com/ory/hydra-consent-app-go/consentapp /usr/bin/consentapp

CMD ["consentapp"]