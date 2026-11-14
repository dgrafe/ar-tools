add_executable(ar-test main.cpp BIP39_tests.cpp SHA256_tests.cpp SHA384_tests.cpp BASE64_tests.cpp BASE64url_tests.cpp PEM_tests.cpp WalletRecovery_tests.cpp Transaction_tests.cpp Protocol_tests.cpp)

target_link_libraries(ar-test
 PRIVATE
  GTest::GTest
  artools)

# Copy the arweave-js reference fixture next to the test binary so the
# reference test can load it regardless of the working directory.
add_custom_command(TARGET ar-test POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          ${CMAKE_CURRENT_SOURCE_DIR}/fixtures
          $<TARGET_FILE_DIR:ar-test>/fixtures)

add_test(ar-test_gtests ar-test)