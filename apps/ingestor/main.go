package main

import (
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"github.com/shieldrasp/ingestor/internal/server"
	pb "github.com/shieldrasp/ingestor/pkg/proto/ingestor"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "50051"
	}

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	// Register services and Kafka producer integration here
	pb.RegisterIngestorServiceServer(grpcServer, server.NewIngestorServer())

	log.Printf("Ingestor running on port %s", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
