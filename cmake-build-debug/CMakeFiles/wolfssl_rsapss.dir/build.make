# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "D:\Program Files\JetBrains\CLion 2018.3.4\bin\cmake\win\bin\cmake.exe"

# The command to remove a file.
RM = "D:\Program Files\JetBrains\CLion 2018.3.4\bin\cmake\win\bin\cmake.exe" -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = C:\Users\Administrator\CLionProjects\wolfssl_rsapss

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/wolfssl_rsapss.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/wolfssl_rsapss.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/wolfssl_rsapss.dir/flags.make

CMakeFiles/wolfssl_rsapss.dir/main.c.obj: CMakeFiles/wolfssl_rsapss.dir/flags.make
CMakeFiles/wolfssl_rsapss.dir/main.c.obj: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/wolfssl_rsapss.dir/main.c.obj"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\wolfssl_rsapss.dir\main.c.obj   -c C:\Users\Administrator\CLionProjects\wolfssl_rsapss\main.c

CMakeFiles/wolfssl_rsapss.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wolfssl_rsapss.dir/main.c.i"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\Administrator\CLionProjects\wolfssl_rsapss\main.c > CMakeFiles\wolfssl_rsapss.dir\main.c.i

CMakeFiles/wolfssl_rsapss.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wolfssl_rsapss.dir/main.c.s"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\Administrator\CLionProjects\wolfssl_rsapss\main.c -o CMakeFiles\wolfssl_rsapss.dir\main.c.s

CMakeFiles/wolfssl_rsapss.dir/rsa.c.obj: CMakeFiles/wolfssl_rsapss.dir/flags.make
CMakeFiles/wolfssl_rsapss.dir/rsa.c.obj: ../rsa.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/wolfssl_rsapss.dir/rsa.c.obj"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\wolfssl_rsapss.dir\rsa.c.obj   -c C:\Users\Administrator\CLionProjects\wolfssl_rsapss\rsa.c

CMakeFiles/wolfssl_rsapss.dir/rsa.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wolfssl_rsapss.dir/rsa.c.i"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\Administrator\CLionProjects\wolfssl_rsapss\rsa.c > CMakeFiles\wolfssl_rsapss.dir\rsa.c.i

CMakeFiles/wolfssl_rsapss.dir/rsa.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wolfssl_rsapss.dir/rsa.c.s"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\Administrator\CLionProjects\wolfssl_rsapss\rsa.c -o CMakeFiles\wolfssl_rsapss.dir\rsa.c.s

CMakeFiles/wolfssl_rsapss.dir/integer.c.obj: CMakeFiles/wolfssl_rsapss.dir/flags.make
CMakeFiles/wolfssl_rsapss.dir/integer.c.obj: ../integer.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/wolfssl_rsapss.dir/integer.c.obj"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\wolfssl_rsapss.dir\integer.c.obj   -c C:\Users\Administrator\CLionProjects\wolfssl_rsapss\integer.c

CMakeFiles/wolfssl_rsapss.dir/integer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wolfssl_rsapss.dir/integer.c.i"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\Administrator\CLionProjects\wolfssl_rsapss\integer.c > CMakeFiles\wolfssl_rsapss.dir\integer.c.i

CMakeFiles/wolfssl_rsapss.dir/integer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wolfssl_rsapss.dir/integer.c.s"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\Administrator\CLionProjects\wolfssl_rsapss\integer.c -o CMakeFiles\wolfssl_rsapss.dir\integer.c.s

CMakeFiles/wolfssl_rsapss.dir/memory.c.obj: CMakeFiles/wolfssl_rsapss.dir/flags.make
CMakeFiles/wolfssl_rsapss.dir/memory.c.obj: ../memory.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/wolfssl_rsapss.dir/memory.c.obj"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\wolfssl_rsapss.dir\memory.c.obj   -c C:\Users\Administrator\CLionProjects\wolfssl_rsapss\memory.c

CMakeFiles/wolfssl_rsapss.dir/memory.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wolfssl_rsapss.dir/memory.c.i"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\Administrator\CLionProjects\wolfssl_rsapss\memory.c > CMakeFiles\wolfssl_rsapss.dir\memory.c.i

CMakeFiles/wolfssl_rsapss.dir/memory.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wolfssl_rsapss.dir/memory.c.s"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\Administrator\CLionProjects\wolfssl_rsapss\memory.c -o CMakeFiles\wolfssl_rsapss.dir\memory.c.s

CMakeFiles/wolfssl_rsapss.dir/random.c.obj: CMakeFiles/wolfssl_rsapss.dir/flags.make
CMakeFiles/wolfssl_rsapss.dir/random.c.obj: ../random.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/wolfssl_rsapss.dir/random.c.obj"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\wolfssl_rsapss.dir\random.c.obj   -c C:\Users\Administrator\CLionProjects\wolfssl_rsapss\random.c

CMakeFiles/wolfssl_rsapss.dir/random.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wolfssl_rsapss.dir/random.c.i"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\Administrator\CLionProjects\wolfssl_rsapss\random.c > CMakeFiles\wolfssl_rsapss.dir\random.c.i

CMakeFiles/wolfssl_rsapss.dir/random.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wolfssl_rsapss.dir/random.c.s"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\Administrator\CLionProjects\wolfssl_rsapss\random.c -o CMakeFiles\wolfssl_rsapss.dir\random.c.s

CMakeFiles/wolfssl_rsapss.dir/sha256.c.obj: CMakeFiles/wolfssl_rsapss.dir/flags.make
CMakeFiles/wolfssl_rsapss.dir/sha256.c.obj: ../sha256.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/wolfssl_rsapss.dir/sha256.c.obj"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\wolfssl_rsapss.dir\sha256.c.obj   -c C:\Users\Administrator\CLionProjects\wolfssl_rsapss\sha256.c

CMakeFiles/wolfssl_rsapss.dir/sha256.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wolfssl_rsapss.dir/sha256.c.i"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\Administrator\CLionProjects\wolfssl_rsapss\sha256.c > CMakeFiles\wolfssl_rsapss.dir\sha256.c.i

CMakeFiles/wolfssl_rsapss.dir/sha256.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wolfssl_rsapss.dir/sha256.c.s"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\Administrator\CLionProjects\wolfssl_rsapss\sha256.c -o CMakeFiles\wolfssl_rsapss.dir\sha256.c.s

CMakeFiles/wolfssl_rsapss.dir/misc.c.obj: CMakeFiles/wolfssl_rsapss.dir/flags.make
CMakeFiles/wolfssl_rsapss.dir/misc.c.obj: ../misc.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/wolfssl_rsapss.dir/misc.c.obj"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\wolfssl_rsapss.dir\misc.c.obj   -c C:\Users\Administrator\CLionProjects\wolfssl_rsapss\misc.c

CMakeFiles/wolfssl_rsapss.dir/misc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wolfssl_rsapss.dir/misc.c.i"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\Administrator\CLionProjects\wolfssl_rsapss\misc.c > CMakeFiles\wolfssl_rsapss.dir\misc.c.i

CMakeFiles/wolfssl_rsapss.dir/misc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wolfssl_rsapss.dir/misc.c.s"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\Administrator\CLionProjects\wolfssl_rsapss\misc.c -o CMakeFiles\wolfssl_rsapss.dir\misc.c.s

CMakeFiles/wolfssl_rsapss.dir/hash.c.obj: CMakeFiles/wolfssl_rsapss.dir/flags.make
CMakeFiles/wolfssl_rsapss.dir/hash.c.obj: ../hash.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/wolfssl_rsapss.dir/hash.c.obj"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\wolfssl_rsapss.dir\hash.c.obj   -c C:\Users\Administrator\CLionProjects\wolfssl_rsapss\hash.c

CMakeFiles/wolfssl_rsapss.dir/hash.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wolfssl_rsapss.dir/hash.c.i"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\Administrator\CLionProjects\wolfssl_rsapss\hash.c > CMakeFiles\wolfssl_rsapss.dir\hash.c.i

CMakeFiles/wolfssl_rsapss.dir/hash.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wolfssl_rsapss.dir/hash.c.s"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\Administrator\CLionProjects\wolfssl_rsapss\hash.c -o CMakeFiles\wolfssl_rsapss.dir\hash.c.s

CMakeFiles/wolfssl_rsapss.dir/wolfmath.c.obj: CMakeFiles/wolfssl_rsapss.dir/flags.make
CMakeFiles/wolfssl_rsapss.dir/wolfmath.c.obj: ../wolfmath.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object CMakeFiles/wolfssl_rsapss.dir/wolfmath.c.obj"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\wolfssl_rsapss.dir\wolfmath.c.obj   -c C:\Users\Administrator\CLionProjects\wolfssl_rsapss\wolfmath.c

CMakeFiles/wolfssl_rsapss.dir/wolfmath.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wolfssl_rsapss.dir/wolfmath.c.i"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\Administrator\CLionProjects\wolfssl_rsapss\wolfmath.c > CMakeFiles\wolfssl_rsapss.dir\wolfmath.c.i

CMakeFiles/wolfssl_rsapss.dir/wolfmath.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wolfssl_rsapss.dir/wolfmath.c.s"
	C:\MinGW\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\Administrator\CLionProjects\wolfssl_rsapss\wolfmath.c -o CMakeFiles\wolfssl_rsapss.dir\wolfmath.c.s

# Object files for target wolfssl_rsapss
wolfssl_rsapss_OBJECTS = \
"CMakeFiles/wolfssl_rsapss.dir/main.c.obj" \
"CMakeFiles/wolfssl_rsapss.dir/rsa.c.obj" \
"CMakeFiles/wolfssl_rsapss.dir/integer.c.obj" \
"CMakeFiles/wolfssl_rsapss.dir/memory.c.obj" \
"CMakeFiles/wolfssl_rsapss.dir/random.c.obj" \
"CMakeFiles/wolfssl_rsapss.dir/sha256.c.obj" \
"CMakeFiles/wolfssl_rsapss.dir/misc.c.obj" \
"CMakeFiles/wolfssl_rsapss.dir/hash.c.obj" \
"CMakeFiles/wolfssl_rsapss.dir/wolfmath.c.obj"

# External object files for target wolfssl_rsapss
wolfssl_rsapss_EXTERNAL_OBJECTS =

wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/main.c.obj
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/rsa.c.obj
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/integer.c.obj
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/memory.c.obj
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/random.c.obj
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/sha256.c.obj
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/misc.c.obj
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/hash.c.obj
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/wolfmath.c.obj
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/build.make
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/linklibs.rsp
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/objects1.rsp
wolfssl_rsapss.exe: CMakeFiles/wolfssl_rsapss.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Linking C executable wolfssl_rsapss.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\wolfssl_rsapss.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/wolfssl_rsapss.dir/build: wolfssl_rsapss.exe

.PHONY : CMakeFiles/wolfssl_rsapss.dir/build

CMakeFiles/wolfssl_rsapss.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\wolfssl_rsapss.dir\cmake_clean.cmake
.PHONY : CMakeFiles/wolfssl_rsapss.dir/clean

CMakeFiles/wolfssl_rsapss.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" C:\Users\Administrator\CLionProjects\wolfssl_rsapss C:\Users\Administrator\CLionProjects\wolfssl_rsapss C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug C:\Users\Administrator\CLionProjects\wolfssl_rsapss\cmake-build-debug\CMakeFiles\wolfssl_rsapss.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/wolfssl_rsapss.dir/depend

