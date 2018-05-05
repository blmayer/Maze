# Maze

>Maze is a project of creating tools for a safer web, it brings a web browser and a web server written in C. These B2B (Beginner to Beginner) applications aims at helping students to learn how clients and servers interact since the creator has insufficient knowledge of C programming. Although simplicity is the main feature of Maze, we plan to make it RFC 2616 compliant and as complete as possible. 

Its components are:

- Servrian: The HTTP/1.1 web server;
- Maze: The browser;
- webng: a shared library; &
- randomstr: a random strings generator.

## Compiling the whole project

Simply change to the Maze directory and run:

`make`

## Getting binaries

So far binaries have not been compiled, but when they are done they will be found under `bin/<$arch>/`, in the future I plan to support more systems.

## Installing binaries and libraries

Run `make install` with root privileges, it will install under */usr/local/*.

## Dependencies

- openssl;
- A C compiler; &
- make.

## Subprojects

### Servrian

Servrian is a small and simple HTTP 1.1 server.

#### The way it works, or tries to

The main source file, [main.c](src/servrian/main.c), opens a TCP socket at port 5000, or at a specified one, and stays listening for incoming connections. Once one connection is made it is forked and the request is processed in parallel by one of the functions defined in separate header files, this means the socket will stay listening to new connections while other processes respond. This request is handled by a function defined in the file [receive.c](src/servrian/receive.c) that reads and interprets the header of the request, passing its attributes to the specific function, which generates a response for that. It has functions in separate files for modularity: [get.c](src/servrian/get.c), [head.c](src/servrian/head.c) and [post.c](src/servrian/post.c)

#### Compiling

To compile this project clone this repository or download all files, change to the Maze directory and run the command:

`make servrian`

#### Running Servrian

You can pass some parameters in the command line to configure Servrian, they are:

- `-h` or `--help` : show a help message;
- `-p` or `--port` : specify the port to listen, default 5000;
- `-d` or `--dir` : use as path to the webpages dir, default `./webpages/`.

### Maze 

Maze tries to browse the web in a faster and safer manner.

### The way it works, or tries to

The main source files, are located in *src/\**, there are some utilities that must be built together.

#### Compiling

To compile this project clone this repository or download all files, change to the Maze directory and run the command:

`make servrian`

#### Running Maze

Type `maze <website>` in your commandline, eg. `maze www.google.com`. 

## Current work

- Creating a graphical interface;

## To-do

There are lots of things to do, the ones in my mind now are listed below.

- Support PUT, DELETE and UPDATE requests (I don't know what for);
- Support wide characters;
- Use encryption for logged in users; &
- Pipe logging.

## Meta

Created by: Brian Mayer - bleemayer@gmail.com	
Inital commit: Mar, 14, 2018
Distributed under The GNU GPL v2. See [LICENSE] for more information.

## Contributing

Check the *contributing* file for details, but, in advance, it is pretty intuitive and straightforward.

## Notes

### MacOS

- Compiling on MacOS with the default C compiler, clang, may give warnings, but compilation finishes without errors;
- You may need to specify the include path to the openssl library because it is, sometimes, in a different place.

### Windows

- Compiling on Windows with Cygwin does not give any warning, but at run time there are several stack traces, I will investigate that.
