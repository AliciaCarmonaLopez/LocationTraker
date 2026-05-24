#!/bin/bash

# Run from the Device/ folder:  bash start-devices.sh

cd "$(dirname "$0")"

PORT=5041 DEVICE_ID=device-001 node device.js &
PORT=5044 DEVICE_ID=device-002 node device.js &
PORT=5045 DEVICE_ID=device-003 node device.js &

echo "Started 3 device instances:"
echo "  device-001 → http://localhost:5041/pegatina"
echo "  device-002 → http://localhost:5044/pegatina"
echo "  device-003 → http://localhost:5045/pegatina"
echo ""
echo "Press Ctrl+C to stop all."

wait