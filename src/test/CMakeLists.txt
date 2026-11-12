# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.
add_executable(test_sv2
  main.cpp
)

add_windows_application_manifest(test_sv2)

# Link all required libraries in a single keyword-style invocation to avoid
# mixing plain and keyword signatures (prevents duplicate library warnings too).
target_link_libraries(test_sv2
  PRIVATE
    core_interface
    Boost::headers
    bitcoin_sv2
    $<$<BOOL:${ENABLE_IPC}>:bitcoin_ipc>
)

target_sources(test_sv2
PRIVATE
  util/net.cpp
  net_backport_tests.cpp
  sv2_test_setup.cpp
  sv2_connman_tester.cpp
  sv2_connman_tests.cpp
  sv2_noise_tests.cpp
  sv2_transport_tests.cpp
  sv2_messages_tests.cpp
  sv2_mock_mining.cpp
  sv2_tp_tester.cpp
  sv2_template_provider_tests.cpp
  sv2_tester_lifecycle_tests.cpp
)

# Ensure Cap'n Proto generated headers (e.g. src/ipc/capnp/init.capnp.h) are
# generated before compiling tests that include them directly. Only applies
# when IPC is enabled.
if(ENABLE_IPC)
  target_sources(test_sv2 PRIVATE ipc_process_tests.cpp ipc_serialized_tests.cpp)
  if(TARGET bitcoin_ipc_headers)
    add_dependencies(test_sv2 bitcoin_ipc_headers)
  endif()
  add_dependencies(test_sv2 bitcoin_ipc)
endif()

# Allow direct includes of generated headers like <src/ipc/...> when IPC is enabled
if(ENABLE_IPC)
  target_include_directories(test_sv2 PRIVATE ${CMAKE_BINARY_DIR})
endif()

if(ENABLE_IPC AND TARGET Libmultiprocess::multiprocess)
  # test_sv2 directly includes generated IPC headers (init.capnp.h) which in turn
  # include libmultiprocess headers (mp/proxy.capnp.h). When using external
  # libmultiprocess, link the imported target to provide the necessary include paths.
  target_link_libraries(test_sv2 PRIVATE Libmultiprocess::multiprocess)
endif()

function(add_boost_test source_file)
  if(NOT EXISTS ${source_file})
    return()
  endif()

  file(READ "${source_file}" source_file_content)
  string(REGEX
    MATCHALL "(BOOST_FIXTURE_TEST_SUITE|BOOST_AUTO_TEST_SUITE)\\(([A-Za-z0-9_]+)"
    test_suite_macro "${source_file_content}"
  )
  list(TRANSFORM test_suite_macro
    REPLACE "(BOOST_FIXTURE_TEST_SUITE|BOOST_AUTO_TEST_SUITE)\\(" ""
  )
  foreach(test_suite_name IN LISTS test_suite_macro)
    add_test(NAME ${test_suite_name}
      COMMAND test_sv2 --run_test=${test_suite_name} --catch_system_error=no --log_level=test_suite -- DEBUG_LOG_OUT
    )
    set_property(TEST ${test_suite_name} PROPERTY
      SKIP_REGULAR_EXPRESSION "no test cases matching filter"
    )
  endforeach()
endfunction()

function(add_all_test_targets)
  get_target_property(test_source_dir test_sv2 SOURCE_DIR)
  get_target_property(test_sources test_sv2 SOURCES)
  foreach(test_source ${test_sources})
    cmake_path(IS_RELATIVE test_source result)
    if(result)
      cmake_path(APPEND test_source_dir ${test_source} OUTPUT_VARIABLE test_source)
    endif()
    add_boost_test(${test_source})
  endforeach()
endfunction()

add_all_test_targets()

install_binary_component(test_sv2)
