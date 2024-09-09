.PHONY: all app-walletshield http_proxy clean


all: app-walletshield http_proxy

app-walletshield:
	make -C apps/walletshield

http_proxy:
	cd server_plugins/cbor_plugins/http_proxy/cmd/http_proxy; go build

clean:
	rm -f \
		apps/walletshield/walletshield \
		server_plugins/cbor_plugins/http_proxy/cmd/http_proxy/http_proxy
