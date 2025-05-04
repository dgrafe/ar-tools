add_executable(ar-test main.cpp BIP39_tests.cpp SHA256_tests.cpp BASE64_tests.cpp BASE64url_tests.cpp PEM_tests.cpp WalletRecovery_tests.cpp)

target_link_libraries(ar-test
 PRIVATE
  GTest::GTest
  artools)

add_test(ar-test_gtests ar-test)