# Generated by BoostInstall.cmake for boost_assert-1.85.0

include(CMakeFindDependencyMacro)

if(NOT boost_config_FOUND)
  find_dependency(boost_config 1.85.0 EXACT)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/boost_assert-targets.cmake")
