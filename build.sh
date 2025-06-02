#!/bin/bash
set -e

IMAGE_NAME="hybridids-build"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="/opt/hybridids"

echo "[build.sh]: Building a Docker image..."
docker build -t $IMAGE_NAME .

echo "[build.sh]: Starting the build inside the container..."
docker run --rm -it \
  -v "$PWD":/app \
  -w /app \
  $IMAGE_NAME \
  bash -c "
    echo '[*] Cleaning build directory...'
    rm -rf build

    echo '[*] Installing dependencies with Conan...'
    [ -f ~/.conan2/profiles/default ] || conan profile detect
    conan install . --output-folder=build --build=missing

    echo '[*] Configuring CMake with tests enabled...'
    cmake -S . -B build \
      -DCMAKE_TOOLCHAIN_FILE=build/build/Release/generators/conan_toolchain.cmake \
      -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_TESTS=ON

    echo '[*] Building the project...'
    cmake --build build

    echo '[*] Running unit tests...'
    cd build
    ctest -V --output-on-failure
  "

echo "[build.sh]: Assembly complete."

echo "[build.sh]: Installing HybridIDS in $DEPLOY_DIR..."

sudo mkdir -p "$DEPLOY_DIR/bin"
sudo mkdir -p "$DEPLOY_DIR/config"
sudo mkdir -p "$DEPLOY_DIR/logs"

sudo cp "$PROJECT_DIR/bin/hybridIDS" "$DEPLOY_DIR/bin/"

if [ -d "$PROJECT_DIR/config" ]; then
  sudo cp -r "$PROJECT_DIR/config/"* "$DEPLOY_DIR/config/"
fi

echo "[build.sh]: Create a systemd unit file..."

sudo bash -c "cat > /etc/systemd/system/hybridids.service <<EOF
[Unit]
Description=HybridIDS Intrusion Detection Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$DEPLOY_DIR
ExecStart=$DEPLOY_DIR/bin/hybridIDS
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
"

echo "[build.sh]: Updating systemd..."
sudo systemctl daemon-reload
sudo systemctl enable hybridids.service

echo "[build.sh]: Installation complete!"
echo "The service of the hybridIDS is launched as follows:"
echo "  sudo systemctl start hybridids.service"
echo "Logs can be viewed at the address:"
echo "  /opt/hybridids/logs/hibridIDS.log"


read -p "[build.sh]: Clear temporary build files (build/, bin/ and etc.)? [y/N] " confirm

if [[ "$confirm" =~ ^[Yy]$ ]]; then
  echo "[build.sh]: Deleting temporary files..."
  sudo rm -rf build/ bin/ CMakeUserPresets.json .Dockerfile.swo .Dockerfile.swp
  echo "[build.sh]: Cleaning completed."
else
  echo "[build.sh]: Temporary files have been saved."
fi