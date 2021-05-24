# Maze

>Maze is a project of creating tools for a safer web, it brings a web browser written in C. 
>These B2B (Beginner to Beginner) applications aims at helping students to learn how clients
>and servers interact since the creator has insufficient knowledge of C programming.
>Although simplicity is the main feature of Maze, we plan to make it RFC 2616 compliant
> and as complete as possible. 

Its components are:

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

- A C compiler; &
- make.


### The way it works, or tries to

The main source files, are located in _src/*_, there are some utilities that must be built together. It resembles Servrian in a certain way, it's modular: we have separated files for each HTTP request, for now, [get.c](src/maze/get.c).


### Compiling

To compile this project clone this repository or download all files, change to the Maze directory and run the command:

`make maze`


### Running Maze

Type `maze <website>` in your commandline, eg. `maze www.google.com`. 


## libwebng

Auxiliary shared library for encrypting and decrypting requests, parsing URLs, requests and responses &c. To discover what it provides please inspect the file [src/webng/webng.h](src/webng/webng.h).


### Compiling

Simply run make libs.


### Linking it against your programs

After installed just follow the conventional way, add `-lwebng` to your linker flags.


# Meta

Created by: Brian Mayer - bleemayer@gmail.com	
Inital commit: Mar, 14, 2018
Distributed under The GNU GPL v2. See [LICENSE](docs/LICENSE) for more information.


## Current work

- Making this work


## To-do

There are lots of things to do, the ones in my mind now are listed below.

- Creating a graphical interface;
- Support PUT, DELETE and UPDATE requests (I don't know what for);
- Support wide characters;
- Use encryption for logged in users; &
- Pipe logging.


## Contributing

Check the *contributing* file for details, but, in advance, it is pretty intuitive and straightforward.


## Notes


### MacOS

- Compiling on MacOS with the default C compiler, clang, may give warnings, but compilation finishes without errors;
- You may need to specify the include path to the openssl library because it is, sometimes, in a different place.


### Windows

- Compiling on Windows with Cygwin does not give any warning, but at run time there are several stack traces, I will investigate that.
