#!/bin/bash
echo "📊 Container Status:"
docker-compose ps

echo ""
echo "🔧 Health Checks:"
for port in 5001 5002 5003; do
    if curl -s "http://localhost:$port/health" > /dev/null 2>&1; then
        echo "  ✅ Port $port - Healthy"
    else
        echo "  ❌ Port $port - Not responding"
    fi
done
