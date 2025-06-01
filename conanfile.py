from conan import ConanFile
from conan.tools.cmake import CMake, cmake_layout

class HybridIDSConan(ConanFile):
    name = "hybridIDS"
    version = "0.1"
    settings = "os", "compiler", "build_type", "arch"
    requires = (
        "libpcap/1.10.1",
        "gtest/1.14.0",
        "nlohmann_json/3.11.2",
    )
    generators = "CMakeDeps", "CMakeToolchain"
    default_options = {
        "gtest/*:shared": True
    }

    def layout(self):
        cmake_layout(self)
