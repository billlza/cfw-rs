# syntax=docker/dockerfile:1.7
FROM golang:1.26.6@sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=readonly -trimpath -ldflags='-s -w -buildid=' -o /out/physical-collector .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=build --chown=nonroot:nonroot /out/physical-collector /physical-collector
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/physical-collector"]
