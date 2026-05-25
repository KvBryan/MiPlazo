package main

import (
	"log"
	"net/http"
	"os"

	"miplazo/internal/config"
	"miplazo/internal/router"
)

func main() {
	log.Println("Iniciando la aplicación MiPlazo...")

	// Evaluar el entorno de ejecución
	env := os.Getenv("ENV")
	jwtSecretEnv := os.Getenv("JWT_SECRET")

	if jwtSecretEnv == "" {
		if env == "production" {
			log.Fatal("Error crítico de seguridad: la variable de entorno JWT_SECRET es obligatoria en producción y no está configurada")
		} else {
			log.Println("⚠️ Advertencia: Usando clave secreta de desarrollo local")
			os.Setenv("JWT_SECRET", "MiPlazoLocalDevSecret2026")
		}
	}

	// Inicializar la conexión a la base de datos
	db, err := config.ConnectDB()
	if err != nil {
		log.Fatalf("Error crítico al inicializar la base de datos: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Advertencia: error al cerrar la conexión de la base de datos: %v", err)
		} else {
			log.Println("Conexión a la base de datos cerrada limpiamente.")
		}
	}()

	log.Println("Conexión a la base de datos PostgreSQL establecida correctamente y verificada.")

	// Inicializar el router de la aplicación
	r := router.NewRouter(db)

	// Configurar e iniciar el servidor HTTP
	port := ":8080"
	log.Printf("Servidor escuchando de forma segura en http://localhost%s", port)
	if err := http.ListenAndServe(port, r); err != nil {
		log.Fatalf("Error crítico: el servidor HTTP no pudo iniciar: %v", err)
	}
}
