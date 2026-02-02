build:
	go build -o out

run: build
	./out

clean:
	rm out