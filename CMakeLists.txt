project(kubescape-ebpf-engine)

cmake_minimum_required(VERSION 2.8.5)

set(FALCO_DEPENDENCY_DIR "${PROJECT_SOURCE_DIR}/dependencies/falco-libs")
set(FALCO_DEPENDENCY_BINARY_DIR "${FALCO_DEPENDENCY_DIR}/build")

set(CMAKE_BUILD_TYPE Debug)

include_directories(${FALCO_DEPENDENCY_DIR}/userspace/libsinsp)
include_directories(${FALCO_DEPENDENCY_DIR}/build/tbb-prefix/src/tbb/include)
include_directories(${FALCO_DEPENDENCY_DIR}/userspace/libscap)
include_directories(${FALCO_DEPENDENCY_DIR}/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/inc)
include_directories(${FALCO_DEPENDENCY_BINARY_DIR}/common)

# add_compile_options(-fsanitize=address)
# add_link_options(-fsanitize=address)

add_executable(main
	${PROJECT_SOURCE_DIR}/src/main.cpp
	# ${PROJECT_SOURCE_DIR}/main.cpp
	${PROJECT_SOURCE_DIR}/src/falco-libs.cpp
	${PROJECT_SOURCE_DIR}/src/cli-parser.c
)

target_link_libraries(main
	${FALCO_DEPENDENCY_BINARY_DIR}/libsinsp/libsinsp.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/libscap.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/engine/udig/libscap_engine_udig.a
	${FALCO_DEPENDENCY_BINARY_DIR}/b64-prefix/src/b64/src/libb64.a
	${FALCO_DEPENDENCY_BINARY_DIR}/jq-prefix/src/jq/modules/oniguruma/src/.libs/libonig.a
	${FALCO_DEPENDENCY_BINARY_DIR}/jq-prefix/src/jq/.libs/libjq.a
	${FALCO_DEPENDENCY_BINARY_DIR}/jq-prefix/src/jq/target/lib/libonig.a
	${FALCO_DEPENDENCY_BINARY_DIR}/jq-prefix/src/jq/target/lib/libjq.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/libscap_engine_util.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/engine/source_plugin/libscap_engine_source_plugin.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/engine/kmod/libscap_engine_kmod.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/engine/noop/libscap_engine_noop.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/engine/test_input/libscap_engine_test_input.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/engine/savefile/libscap_engine_savefile.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/engine/bpf/libscap_engine_bpf.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/libscap_event_schema.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/engine/gvisor/libscap_engine_gvisor.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/engine/nodriver/libscap_engine_nodriver.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/libdriver_event_schema.a
	${FALCO_DEPENDENCY_BINARY_DIR}/curl-prefix/src/curl/lib/.libs/libcurl.a
	${FALCO_DEPENDENCY_BINARY_DIR}/protobuf-prefix/src/protobuf/src/.libs/libprotobuf-lite.a
	${FALCO_DEPENDENCY_BINARY_DIR}/protobuf-prefix/src/protobuf/src/.libs/libprotobuf.a
	${FALCO_DEPENDENCY_BINARY_DIR}/protobuf-prefix/src/protobuf/src/.libs/libprotoc.a
	${FALCO_DEPENDENCY_BINARY_DIR}/protobuf-prefix/src/protobuf/target/lib/libprotobuf-lite.a
	${FALCO_DEPENDENCY_BINARY_DIR}/protobuf-prefix/src/protobuf/target/lib/libprotobuf.a
	${FALCO_DEPENDENCY_BINARY_DIR}/protobuf-prefix/src/protobuf/target/lib/libprotoc.a
	${FALCO_DEPENDENCY_BINARY_DIR}/zlib-prefix/src/zlib/libz.a
	${FALCO_DEPENDENCY_BINARY_DIR}/tbb-prefix/src/tbb/build/lib_release/libtbbmalloc.a
	${FALCO_DEPENDENCY_BINARY_DIR}/tbb-prefix/src/tbb/build/lib_release/libtbb.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/libgrpc++.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/libgrpc.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/re2/libre2.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/target/lib/libre2.a
	${FALCO_DEPENDENCY_BINARY_DIR}/libscap/linux/libscap_platform.a
	# ${FALCO_DEPENDENCY_BINARY_DIR}/re2-prefix/src/re2/lib/libre2.a
	# ${FALCO_DEPENDENCY_BINARY_DIR}/re2-prefix/build/libre2.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/libaddress_sorting.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/libgpr.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/libupb.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags_config.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags_program_name.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags_commandlineflag_internal.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags_parse.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags_usage.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags_usage_internal.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags_commandlineflag.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags_internal.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags_marshalling.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags_reflection.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/debugging/libabsl_leak_check.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/debugging/libabsl_leak_check_disable.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/debugging/libabsl_examine_stack.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/debugging/libabsl_failure_signal_handler.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/types/libabsl_bad_variant_access.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/types/libabsl_bad_any_cast_impl.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/types/libabsl_bad_optional_access.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/synchronization/libabsl_graphcycles_internal.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/synchronization/libabsl_synchronization.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/debugging/libabsl_symbolize.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/debugging/libabsl_demangle_internal.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/container/libabsl_hashtablez_sampler.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/container/libabsl_raw_hash_set.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/strings/libabsl_cord.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/strings/libabsl_cordz_functions.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/strings/libabsl_strings.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/strings/libabsl_strings_internal.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/strings/libabsl_str_format_internal.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/strings/libabsl_cordz_info.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/debugging/libabsl_stacktrace.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/debugging/libabsl_debugging_internal.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/strings/libabsl_cord_internal.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/strings/libabsl_cordz_sample_token.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/strings/libabsl_cordz_handle.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/hash/libabsl_hash.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/hash/libabsl_city.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/hash/libabsl_low_level_hash.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/time/libabsl_civil_time.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/time/libabsl_time.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/time/libabsl_time_zone.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/numeric/libabsl_int128.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/status/libabsl_statusor.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/status/libabsl_status.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/base/libabsl_base.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/base/libabsl_scoped_set_env.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/base/libabsl_spinlock_wait.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/base/libabsl_log_severity.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/base/libabsl_throw_delegate.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/base/libabsl_raw_logging_internal.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/base/libabsl_strerror.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/base/libabsl_malloc_internal.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/random/libabsl_random_internal_distribution_test_util.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/random/libabsl_random_distributions.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/random/libabsl_random_internal_randen_hwaes_impl.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/random/libabsl_random_internal_randen.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/random/libabsl_random_internal_randen_slow.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/random/libabsl_random_internal_randen_hwaes.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/random/libabsl_random_seed_sequences.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/random/libabsl_random_internal_platform.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/random/libabsl_random_internal_pool_urbg.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/random/libabsl_random_internal_seed_material.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/random/libabsl_random_seed_gen_exception.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/profiling/libabsl_periodic_sampler.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/profiling/libabsl_exponential_biased.a
	${FALCO_DEPENDENCY_BINARY_DIR}/grpc-prefix/src/grpc/third_party/abseil-cpp/absl/flags/libabsl_flags_private_handle_accessor.a
	${FALCO_DEPENDENCY_BINARY_DIR}/c-ares-prefix/src/c-ares/src/lib/.libs/libcares.a
	${FALCO_DEPENDENCY_BINARY_DIR}/c-ares-prefix/src/c-ares/target/lib/libcares.a
	${FALCO_DEPENDENCY_BINARY_DIR}/c-ares-prefix/src/c-ares/test/.libs/libgmock.a
	${FALCO_DEPENDENCY_BINARY_DIR}/openssl-prefix/src/openssl/target/lib/libssl.a
	${FALCO_DEPENDENCY_BINARY_DIR}/openssl-prefix/src/openssl/target/lib/libcrypto.a
	${FALCO_DEPENDENCY_BINARY_DIR}/openssl-prefix/src/openssl/libssl.a
	${FALCO_DEPENDENCY_BINARY_DIR}/openssl-prefix/src/openssl/apps/libapps.a
	${FALCO_DEPENDENCY_BINARY_DIR}/openssl-prefix/src/openssl/libcrypto.a
	${FALCO_DEPENDENCY_BINARY_DIR}/openssl-prefix/src/openssl/test/libtestutil.a
	dl
	pthread
	rt
	elf
)
    