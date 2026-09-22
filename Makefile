#comment to force a workflow run

test:
	go test ./...


coverage.txt:
	go test -coverprofile=coverage.txt ./...



coverview: coverage.txt
	go tool cover -html=coverage.txt


clean:
	rm -f bin/*
	rm -f coverage.txt
