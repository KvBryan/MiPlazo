# ==========================================
# FASE 1: Compilación del ejecutable de Go
# ==========================================
FROM golang:1.26-alpine AS builder

# Instalar herramientas necesarias para compilar y dependencias de red
RUN apk add --no-cache git gcc musl-dev

# Establecer directorio de trabajo en el contenedor
WORKDIR /app

# Copiar archivos de dependencias de Go primero (aprovecha la caché de Docker)
COPY go.mod go.sum ./
RUN go mod download

# Copiar todo el código fuente del proyecto
COPY . .

# Compilar el binario optimizado para producción estática (sin CGO, reduce peso)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o miplazo-api ./cmd/api/main.go

# ==========================================
# FASE 2: Entorno de ejecución de producción ligero
# ==========================================
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /root/

# Copiar el binario compilado desde la fase anterior
COPY --from=builder /app/miplazo-api .

# Copiar la carpeta estática del frontend (Esencial para que Chi sirva la interfaz)
COPY --from=builder /app/ui ./ui

# Exponer el puerto del búnker
EXPOSE 8080

# Comando para ejecutar la aplicación
CMD ["./miplazo-api"]
