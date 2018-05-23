.PHONY: tests

tests: parse_URL encode_decode parse_request parse_response create_response \
	encryption

parse_URL: parse_URL.c
	$(CC) $^ -o $@ -lwebng
	@echo "#---- Running test suite --------------------------#"
	@echo "Testing url www.google.com"
	./$@ www.google.com
	@echo "Testing url www.google.com/"
	./$@ www.google.com/
	@echo "Testing url www.google.com:700"
	./$@ www.google.com:700
	@echo "Testing url www.google.com:800/index.html"
	./$@ www.google.com:800/index.html
	@echo "Testing url localhost:5000/"
	./$@ localhost:5000
	@echo "Testing url 127.127.127.127"
	./$@ 127.127.127.127
	@echo "Testing url 127.127.127.127:5000"
	./$@ 127.127.127.127:5000

encode_decode: encode_decode.c
	$(CC) $^ -o $@ -lwebng
	@echo "#---- Running test suite --------------------------#"
	./$@

encryption: encryption.c
	$(CC) $^ -o $@ -lwebng
	@echo "#---- Running test suite --------------------------#"
	./$@

parse_request: parse_request.c
	$(CC) $^ -o $@ -lwebng
	@echo "#---- Running test suite --------------------------#"
	./$@

parse_response: parse_response.c
	$(CC) $^ -o $@ -lwebng
	@echo "#---- Running test suite --------------------------#"
	./$@

create_response: create_response.c
	$(CC) $^ -o $@ -lwebng
	@echo "#---- Running test suite --------------------------#"
	./$@

