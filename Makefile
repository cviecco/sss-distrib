#comment to force a workflow run

test:
	go test ./...


coverage.out:
	go test -coverprofile=coverage.out ./...



coverview: coverage.out
	go tool cover -html=coverage.out


clean:
	rm -f bin/*
	rm -f coverage.out
