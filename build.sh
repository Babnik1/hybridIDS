#!/bin/bash
set -e

IMAGE_NAME="hybridids-build"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="/opt/hybridids"

echo "Собираем Docker образ..."
docker build -t $IMAGE_NAME .

echo "Запускаем сборку внутри контейнера..."
docker run --rm -it \
  -v "$PWD":/app \
  -w /app \
  $IMAGE_NAME \
  bash -c " \
    [ -f ~/.conan2/profiles/default ] || conan profile detect && \
    conan install . --output-folder=build --build=missing && \
    cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/build/Release/generators/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build
  "

echo "Сборка завершена."

echo "Устанавливаем HybridIDS в $DEPLOY_DIR..."

sudo mkdir -p "$DEPLOY_DIR/bin"
sudo mkdir -p "$DEPLOY_DIR/config"
sudo mkdir -p "$DEPLOY_DIR/logs"

sudo cp "$PROJECT_DIR/bin/hybridIDS" "$DEPLOY_DIR/bin/"

if [ -d "$PROJECT_DIR/config" ]; then
  sudo cp -r "$PROJECT_DIR/config/"* "$DEPLOY_DIR/config/"
fi

echo "Создаём systemd unit-файл..."

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

echo "Обновляем systemd..."
sudo systemctl daemon-reload
sudo systemctl enable hybridids.service

echo "Установка завершена!"
echo "Запустить можно так:"
echo "  sudo systemctl start hybridids.service"
echo "Логи можно посмотреть командой:"
echo "  sudo journalctl -u hybridids.service -f"
