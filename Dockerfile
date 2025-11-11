# ---- Build stage ----
FROM golang:1.25 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./src/main.go

FROM scratch

WORKDIR /app
COPY --from=builder /app/main .

EXPOSE 5020
ENTRYPOINT ["/app/main"]
