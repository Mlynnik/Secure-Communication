cmake_minimum_required(VERSION 3.5)

project(client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}")

find_package(GMP REQUIRED)

add_executable(client main.cpp
    AES.h DiffieHellman.h json.hpp Matrix.h RSA.h SHA.h UOV.h)

target_link_libraries(client PRIVATE gmp gmpxx)

include(GNUInstallDirs)
install(TARGETS client
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
