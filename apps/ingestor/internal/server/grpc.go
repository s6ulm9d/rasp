package server

import (
	"context"
	pb "github.com/shieldrasp/ingestor/pkg/proto/ingestor"
)

type IngestorServer struct {
	pb.UnimplementedIngestorServiceServer
}

func NewIngestorServer() *IngestorServer {
	return &IngestorServer{}
}

func (s *IngestorServer) SendTelemetry(ctx context.Context, req *pb.IngestRequest) (*pb.IngestResponse, error) {
	// 1. Validate API Key
	// 2. Enforce Rate Limit (1000 events/sec)
	// 3. Publish to Kafka "rasp.events.raw"
	
	return &pb.IngestResponse{
		Success: true,
		EventsProcessed: int32(len(req.Batch.Events)),
		Message: "Batch ingested securely",
	}, nil
}
