FROM golang:alpine AS build_base
#ENV GOARCH arm64
#ENV GOARCH amd64
RUN apk add --no-cache git gcc ca-certificates libc-dev \
&& mkdir -p /go/src/github.com/librespeed/ \
&& cd /go/src/github.com/librespeed/ \
&& git clone https://github.com/mengskysama/speedtest-go.git
WORKDIR /go/src/github.com/librespeed/speedtest-go
RUN git checkout develop && go build -ldflags "-w -s" -trimpath -o speedtest main.go

FROM alpine:3.15
RUN apk add ca-certificates
WORKDIR /app
COPY --from=build_base /go/src/github.com/librespeed/speedtest-go/speedtest .
COPY --from=build_base /go/src/github.com/librespeed/speedtest-go/web/assets ./assets
COPY --from=build_base /go/src/github.com/librespeed/speedtest-go/settings.toml .

CMD ["./speedtest"]
