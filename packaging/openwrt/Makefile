# OpenWrt package Makefile template for Nexus (supports both .apk on OpenWrt 25+ and .ipk on OpenWrt 24-)
# Place a prebuilt static musl binary (e.g. aarch64-linux-musl / x86_64-linux-musl) at $(PKG_BUILD_DIR)/nexus
# or wire Build/Compile to invoke mcpp with --profile openwrt-musl.

include $(TOPDIR)/rules.mk

PKG_NAME:=nexus
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Nexus Contributors

include $(INCLUDE_DIR)/package.mk

define Package/nexus
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=Nexus C++26 Modular Network Proxy Core
  DEPENDS:=+ca-bundle +kmod-tun +kmod-nft-tproxy +kmod-nft-socket
endef

define Package/nexus/description
  Nexus is a modular C++26 network proxy core supporting SOCKS5, HTTP/2, HTTP/3,
  VLESS/REALITY, Trojan, Shadowsocks 2022, Hysteria2, TUIC, AnyTLS, WireGuard,
  TUN/TPROXY transparent routing, and local/HTTP control APIs.
endef

define Package/nexus/conffiles
/etc/nexus/config.kdl
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	if [ -f "$(CURDIR)/nexus" ]; then \
		$(CP) "$(CURDIR)/nexus" $(PKG_BUILD_DIR)/nexus; \
	fi
endef

define Build/Compile
	test -x $(PKG_BUILD_DIR)/nexus || (echo "Place static musl binary at $(PKG_BUILD_DIR)/nexus" && exit 1)
endef

define Package/nexus/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nexus $(1)/usr/bin/nexus
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./nexus.init $(1)/etc/init.d/nexus
	$(INSTALL_DIR) $(1)/etc/nexus
endef

$(eval $(call BuildPackage,nexus))
