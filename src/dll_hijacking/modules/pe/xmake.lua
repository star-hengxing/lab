add_requires("pedeps")

set_languages("c++17")

target("pe")
    add_rules("module.shared")
    add_files("*.cpp")
    add_packages("pedeps")
