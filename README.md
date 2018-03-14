# Maze

>A small and simple web browser written in C. This B2B (Beginner to Beginner) application, as the creator has little knowledge of C programming, aims at helping students to learn how clients and servers interact, simplicity is the main feature of it, however, we plan to make as complete as possible and RFC 2616 compliant.

## The way it works, or tries to

The main source file, *browser.c*, tries to estabilish a TCP connection, and makes a HTTP request to an URL. Each connection will be a diferent process, a tab in the browser, so we can handle multiple tabs at the same time. This request is handled by a function defined in the file *reqfunc.h* that writes and interprets requests, passing its attributes to the specific function, which generates a response for that.

### Compiling

To compile this project clone this repository or download all files, change to the Maze directory and run the command:

`make`

this should compile without warnings and create a binary in bin/<$arch>, which you can then execute with `./bin/<$arch>/maze`. I recommend that you use the C compiler that ships with Xcode or with GCC, make sure to be using C version 99. On MacOS you can install the GCC version with [Homebrew](https://brew.sh/). I know it compiles on MacOS 10.12.6 with both compilers and on an 64 bit linux.

### Getting binaries

So far I only compiled binaries for MacOS and 64 bit Linux, they can be found under `bin/<$arch>/`, in the future I plan to support more systems.

## Current work

- Initial build; &
- Receive the response of a get request.

## To-do

There are lots of things to do, the ones in my mind now are listed below.

- Support PUT, DELETE and UPDATE requests (I don't know what for);
- Support chunked transfer encoding;
- Support complete path on requests;
- Use encryption for loged in users; &
- Pipe logging.

## Meta

Created by: Brian Mayer - bleemayer@gmail.com	
Inital commit: Mar, 14, 2018
Distributed under The Unlicense. See ``UNLICENSE`` for more information.

## Contributing

Check the *contributing* file for details, but, in advance, it is pretty intuitive and straightforward.

