# Generated by BoostInstall.cmake for boost_date_time-1.85.0

include(CMakeFindDependencyMacro)

if(NOT boost_algorithm_FOUND)
  find_dependency(boost_algorithm 1.85.0 EXACT)
endif()
if(NOT boost_assert_FOUND)
  find_dependency(boost_assert 1.85.0 EXACT)
endif()
if(NOT boost_config_FOUND)
  find_dependency(boost_config 1.85.0 EXACT)
endif()
if(NOT boost_core_FOUND)
  find_dependency(boost_core 1.85.0 EXACT)
endif()
if(NOT boost_io_FOUND)
  find_dependency(boost_io 1.85.0 EXACT)
endif()
if(NOT boost_lexical_cast_FOUND)
  find_dependency(boost_lexical_cast 1.85.0 EXACT)
endif()
if(NOT boost_numeric_conversion_FOUND)
  find_dependency(boost_numeric_conversion 1.85.0 EXACT)
endif()
if(NOT boost_range_FOUND)
  find_dependency(boost_range 1.85.0 EXACT)
endif()
if(NOT boost_smart_ptr_FOUND)
  find_dependency(boost_smart_ptr 1.85.0 EXACT)
endif()
if(NOT boost_static_assert_FOUND)
  find_dependency(boost_static_assert 1.85.0 EXACT)
endif()
if(NOT boost_throw_exception_FOUND)
  find_dependency(boost_throw_exception 1.85.0 EXACT)
endif()
if(NOT boost_tokenizer_FOUND)
  find_dependency(boost_tokenizer 1.85.0 EXACT)
endif()
if(NOT boost_type_traits_FOUND)
  find_dependency(boost_type_traits 1.85.0 EXACT)
endif()
if(NOT boost_utility_FOUND)
  find_dependency(boost_utility 1.85.0 EXACT)
endif()
if(NOT boost_winapi_FOUND)
  find_dependency(boost_winapi 1.85.0 EXACT)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/boost_date_time-targets.cmake")
