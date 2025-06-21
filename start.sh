#!/bin/bash
echo "🚀 Starting vulnerability testing websites..."

docker-compose up -d

echo "⏳ Waiting for containers to be ready..."
sleep 10

echo "📊 Container Status:"
docker-compose ps

echo ""
echo "🌐 Access URLs:"
echo "  🚨 Vulnerable: http://localhost:5001"
echo "  ⚠️  Medium:     http://localhost:5002"
echo "  🔒 Secure:     http://localhost:5003"
echo ""
echo "✅ All websites are ready for testing!"
