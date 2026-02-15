APP_NAME := TailscaleProxy.app
GUI_BINARY := tailscale-proxy-app
CLI_BINARY := tailscale-proxy
CONTENTS_DIR := $(APP_NAME)/Contents
MACOS_DIR := $(CONTENTS_DIR)/MacOS
RESOURCES_DIR := $(CONTENTS_DIR)/Resources

.PHONY: all clean app cli gui

all: cli gui

cli:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(CLI_BINARY) ./cmd/tailscale-proxy

gui:
	go build -ldflags="-s -w" -o $(GUI_BINARY) ./cmd/tailscale-proxy-app

app: gui
	mkdir -p $(MACOS_DIR)
	mkdir -p $(RESOURCES_DIR)
	cp $(GUI_BINARY) $(MACOS_DIR)/
	cp icon.png $(RESOURCES_DIR)/icon.png || true
	# Create Info.plist
	echo '<?xml version="1.0" encoding="UTF-8"?>' > $(CONTENTS_DIR)/Info.plist
	echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' >> $(CONTENTS_DIR)/Info.plist
	echo '<plist version="1.0">' >> $(CONTENTS_DIR)/Info.plist
	echo '<dict>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>CFBundleExecutable</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <string>$(GUI_BINARY)</string>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>CFBundleIconFile</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <string>icon.png</string>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>CFBundleIdentifier</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <string>com.tailscale.proxy-app</string>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>CFBundleName</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <string>Tailscale Proxy App</string>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>CFBundlePackageType</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <string>APPL</string>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>LSUIElement</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <false/>' >> $(CONTENTS_DIR)/Info.plist
	echo '</dict>' >> $(CONTENTS_DIR)/Info.plist
	echo '</plist>' >> $(CONTENTS_DIR)/Info.plist

clean:
	rm -rf $(APP_NAME) $(GUI_BINARY) $(CLI_BINARY) *-stripped
