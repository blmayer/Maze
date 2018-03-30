# Maze

>A small and simple web browser written in C. This B2B (Beginner to Beginner) application aims at helping students to learn how clients and servers interact since the creator has insufficient knowledge of C programming. Although simplicity is the main feature of Maze, we plan to make it RFC 2616 compliant and as complete as possible.

## The way it works, or tries to

The main source file, *browser.c*, tries to estabilish a TCP connection and makes a HTTP request to an URL. Each connection will be a different process (a tab in the browser), so we can handle multiple tabs simultaneously. This request is handled by a function defined in the file *reqfunc.h* that writes, interprets requests, and passes its attributes to a specific function, which generates a response for that.

### Compiling

#### Dependencies

- openssl;
- libweb (see [Randomator](https://github.com/blmayer/Randomator));
- A C compiler; &
- make.

#### Build

To compile this project clone this repository or download all files, change to the Maze directory and run the command:

`make`

this should compile without warnings and create a binary in bin/<$arch>, which you can then execute with `./bin/<$arch>/maze`. I recommend that you use the C compiler that ships with Xcode or with GCC, make sure to use C version 99. On MacOS you can install the GCC version with [Homebrew](https://brew.sh/). It compiles on MacOS 10.12.6 with both compilers and on an 64 bit linux.

### Getting binaries

So far binaries have not been compiled, but when they are done they will be found under `bin/<$arch>/`, in the future I plan to support more systems.

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
Distributed under The Unlicense. See ``LICENSE`` for more information.

## Contributing

Check the *contributing* file for details, but, in advance, it is pretty intuitive and straightforward.

## Notes

### MacOS

- Compiling on MacOS with the default C compiler, clang, may give warnings, but compilation finishes without errors;
- You may need to specify the include path to the openssl library because it is, sometimes, in a different place.

### Windows

- Compiling on Windows with Cygwin does not give any warning, but at run time there are several stack traces, I will investigate that.
