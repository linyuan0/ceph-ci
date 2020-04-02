# This module builds Jaeger after it's dependencies are installed and discovered
# OpenTracing: is built using cmake/modules/BuildOpenTracing.cmake
# Thrift: build using cmake/modules/Buildthrift.cmake
# yaml-cpp, nlhomann-json: are installed locally and then discovered using
# Find<package>.cmake
# Boost Libraries used for building thrift are build and provided by
# cmake/modules/BuildBoost.cmake

function(build_jaeger)
  set(Jaeger_DOWNLOAD_DIR "${CMAKE_SOURCE_DIR}/src/jaegertracing")
  set(Jaeger_SOURCE_DIR "${CMAKE_SOURCE_DIR}/src/jaegertracing/jaeger-client-cpp")
  set(Jaeger_ROOT_DIR "${CMAKE_BINARY_DIR}/external")
  set(Jaeger_BINARY_DIR "${Jaeger_ROOT_DIR}/Jaeger")
  list(APPEND CMAKE_FIND_ROOT_PATH "${CMAKE_BINARY_DIR}/external")
  list(APPEND CMAKE_FIND_ROOT_PATH "/opt/ceph")

  set(Jaeger_CMAKE_ARGS -DCMAKE_POSITION_INDEPENDENT_CODE=ON
			-DBUILD_SHARED_LIBS=ON
			-DHUNTER_ENABLED=OFF
			-DBUILD_TESTING=OFF
			-DJAEGERTRACING_BUILD_EXAMPLES=ON
			-DCMAKE_PREFIX_PATH=${CMAKE_BINARY_DIR}/external
			-DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/external
			-DCMAKE_FIND_ROOT_PATH=${CMAKE_BINARY_DIR}/external
			-DCMAKE_INSTALL_LIBDIR=${CMAKE_BINARY_DIR}/external/lib)

  set(dependencies OpenTracing thrift)
  include(BuildOpenTracing)
  build_opentracing()
  include(Buildthrift)
  build_thrift()
  find_package(yaml-cpp 0.6.0)
  if(NOT yaml-cpp_FOUND)
    include(Buildyaml-cpp)
    build_yamlcpp()
    add_library(yaml-cpp::yaml-cpp SHARED IMPORTED)
    add_dependencies(yaml-cpp::yaml-cpp yaml-cpp)
    set_library_properties_for_external_project(yaml-cpp::yaml-cpp
      yaml-cpp)
    list(APPEND dependencies "yaml-cpp")
  endif()

  message(STATUS "DEPENDENCIES ${dependencies}")
  if(CMAKE_MAKE_PROGRAM MATCHES "make")
    # try to inherit command line arguments passed by parent "make" job
    set(make_cmd $(MAKE))
  else()
    set(make_cmd ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG> --target Jaeger)
  endif()

  include(ExternalProject)
  ExternalProject_Add(Jaeger
    GIT_REPOSITORY https://github.com/ideepika/jaeger-client-cpp.git
    GIT_TAG "hunter-disabled"
    UPDATE_COMMAND ""
    INSTALL_DIR "${CMAKE_BINARY_DIR}/external"
    DOWNLOAD_DIR ${Jaeger_DOWNLOAD_DIR}
    SOURCE_DIR ${Jaeger_SOURCE_DIR}
    PREFIX ${Jaeger_ROOT_DIR}
    CMAKE_ARGS ${Jaeger_CMAKE_ARGS}
    BINARY_DIR ${Jaeger_BINARY_DIR}
    BUILD_COMMAND ${make_cmd}
    INSTALL_COMMAND make install
    DEPENDS "${dependencies}"
    )
endfunction()
