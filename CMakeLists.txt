cmake_minimum_required(VERSION 3.20)
project(cpp-live-transcription VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Crow CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

add_executable(${PROJECT_NAME} src/main.cpp src/deepgram_path.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Crow::Crow
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    Boost::system
)

# Crow otherwise uses standalone Asio, which conflicts with this Beast-based proxy.
target_compile_definitions(${PROJECT_NAME} PRIVATE CROW_USE_BOOST)

include(CTest)
if(BUILD_TESTING)
    add_executable(deepgram_path_test test/deepgram_path_test.cpp src/deepgram_path.cpp)
    target_include_directories(deepgram_path_test PRIVATE src)
    add_test(NAME deepgram_path_test COMMAND deepgram_path_test)
endif()
