.PHONY: all app-walletshield genconfig http_proxy pki clean

all: app-walletshield http_proxy

app-walletshield:
	make -C apps/walletshield

genconfig:
	cd genconfig/cmd/genconfig && go build

http_proxy:
	cd server_plugins/cbor_plugins/http_proxy/cmd/http_proxy; go build

pki:
	make -C pki

clean:
	make -C pki clean
	rm -f \
		apps/walletshield/walletshield \
		genconfig/cmd/genconfig/genconfig \
		server_plugins/cbor_plugins/http_proxy/cmd/http_proxy/http_proxy
