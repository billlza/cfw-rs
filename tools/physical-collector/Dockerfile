# syntax=docker/dockerfile:1.7
FROM golang:1.26.5@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS build

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
