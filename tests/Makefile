.PHONY: tests parse_URL parse_request parse_response create_response x25519_test

LDFLAGS += -lwebng -L ../src/webng/ -I ../src/webng/
export LD_LIBRARY_PATH = ../src/webng/
export LD_INCLUDE_PATH = ../src/webng/

tests: parse_URL parse_request parse_response create_response x25519_test

parse_URL: parse_URL.c
	$(CC) $^ -o $@ $(LDFLAGS)
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

parse_request: parse_request.c
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "#---- Running test suite --------------------------#"
	./$@

parse_response: parse_response.c
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "#---- Running test suite --------------------------#"
	./$@

create_response: create_response.c
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "#---- Running test suite --------------------------#"
	./$@

x25519_test: x25519_test.c
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "#---- Running test suite --------------------------#"
	./$@