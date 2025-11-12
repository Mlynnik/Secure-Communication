cmake_minimum_required(VERSION 3.5)

project(ca LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}")

find_package(GMP REQUIRED)

add_executable(ca main.cpp
    Matrix.h SHA.h UOV.h
)

target_link_libraries(ca PRIVATE gmp gmpxx)

include(GNUInstallDirs)
install(TARGETS ca
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
