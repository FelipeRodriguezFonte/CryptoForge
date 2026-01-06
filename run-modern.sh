#!/bin/bash

echo "================================================"
echo "  CryptoForge - MODERN UI PROTOTYPE"
echo "================================================"
echo ""
echo "Cleaning and rebuilding..."
rm -rf target
mvn clean compile

echo ""
echo "Launching modern UI..."
mvn clean javafx:run
