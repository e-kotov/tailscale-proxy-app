APP_NAME := TailscaleProxy.app
BINARY_NAME := tailscale-proxy-app
CONTENTS_DIR := $(APP_NAME)/Contents
MACOS_DIR := $(CONTENTS_DIR)/MacOS
RESOURCES_DIR := $(CONTENTS_DIR)/Resources

.PHONY: all clean app cli

all: app

app: $(BINARY_NAME)
	mkdir -p $(MACOS_DIR)
	mkdir -p $(RESOURCES_DIR)
	cp $(BINARY_NAME) $(MACOS_DIR)/
	cp icon.png $(RESOURCES_DIR)/icon.png || true
	# Create Info.plist
	echo '<?xml version="1.0" encoding="UTF-8"?>' > $(CONTENTS_DIR)/Info.plist
	echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' >> $(CONTENTS_DIR)/Info.plist
	echo '<plist version="1.0">' >> $(CONTENTS_DIR)/Info.plist
	echo '<dict>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>CFBundleExecutable</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <string>$(BINARY_NAME)</string>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>CFBundleIconFile</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <string>icon.png</string>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>CFBundleIdentifier</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <string>com.tailscale.browser-ext-proxy</string>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>CFBundleName</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <string>Tailscale Proxy</string>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>CFBundlePackageType</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <string>APPL</string>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>LSUIElement</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <false/>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <key>LSEnvironment</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '    <dict>' >> $(CONTENTS_DIR)/Info.plist
	echo '        <key>TS_GUI_MODE</key>' >> $(CONTENTS_DIR)/Info.plist
	echo '        <string>1</string>' >> $(CONTENTS_DIR)/Info.plist
	echo '    </dict>' >> $(CONTENTS_DIR)/Info.plist
	echo '</dict>' >> $(CONTENTS_DIR)/Info.plist
	echo '</plist>' >> $(CONTENTS_DIR)/Info.plist

$(BINARY_NAME): main.go
	go build -o $(BINARY_NAME) .

cli: $(BINARY_NAME)

clean:
	rm -rf $(APP_NAME) $(BINARY_NAME)
