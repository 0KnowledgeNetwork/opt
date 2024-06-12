warped?=true
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

all:
	sh -c 'go build -ldflags ${ldflags};'

clean:
	rm app-walletshield
