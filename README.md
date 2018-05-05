# Maze

>Maze is a project of creating tools for a safer web, it brings a web browser and a web server written in C. These B2B (Beginner to Beginner) applications aims at helping students to learn how clients and servers interact since the creator has insufficient knowledge of C programming. Although simplicity is the main feature of Maze, we plan to make it RFC 2616 compliant and as complete as possible.

## The way it works, or tries to

The main source files, are located in *src/**, there are some utilities that must be built together.

### Compiling

#### Dependencies

- openssl;
- A C compiler; &
- make.

#### Build

To compile this project clone this repository or download all files, change to the Maze directory and run the command:

`make`

this should compile without warnings and create some binaris in src/program/, which you can then execute with `./src/program/program`. I recommend that you use the C compiler that ships with Xcode or with GCC, make sure to use C version 99. On MacOS you can install the GCC version with [Homebrew](https://brew.sh/). It compiles on MacOS 10.12.6 with both compilers and on an 64 bit linux.

### Getting binaries

So far binaries have not been compiled, but when they are done they will be found under `bin/<$arch>/`, in the future I plan to support more systems.

## Current work

- Creating a graphical interface.

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
