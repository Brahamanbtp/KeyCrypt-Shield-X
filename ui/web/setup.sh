#!/bin/bash

# Navigate to web directory
cd "$(dirname "$0")"

echo "🔧 Setting up KeyCrypt Shield X Web UI..."

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Type check
echo "✅ Running type check..."
npm run type-check

echo "✨ Setup complete!"
echo ""
echo "To start development server:"
echo "  npm run dev"
echo ""
echo "To build for production:"
echo "  npm run build"