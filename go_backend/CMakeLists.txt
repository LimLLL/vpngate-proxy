cmake_minimum_required(VERSION 3.16)
project(vpngate_go_bridge LANGUAGES CXX)

set(OPENVPN3_SOURCE_DIR "" CACHE PATH "Pinned OpenVPN 3 Core source tree")
if (NOT EXISTS "${OPENVPN3_SOURCE_DIR}/client/ovpncli.cpp")
    message(FATAL_ERROR "OPENVPN3_SOURCE_DIR must point to the official OpenVPN 3 Core sources")
endif ()

list(APPEND CMAKE_MODULE_PATH "${OPENVPN3_SOURCE_DIR}/cmake")
include(findcoredeps)

add_library(vpngate_bridge SHARED
    bridge.cpp
    "${OPENVPN3_SOURCE_DIR}/client/ovpncli.cpp"
)
target_include_directories(vpngate_bridge PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
add_core_dependencies(vpngate_bridge)
add_json_library(vpngate_bridge)
