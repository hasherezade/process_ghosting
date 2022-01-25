cmake_minimum_required (VERSION 3.0)
project (proc_ghost)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	main.cpp
	util.cpp
	ntdll_undoc.cpp
	pe_hdrs_helper.cpp
	process_env.cpp
)

set (hdrs
	util.h
	ntdll_undoc.h
	ntdll_types.h
	ntddk.h
	pe_hdrs_helper.h
	process_env.h
)

add_executable (proc_ghost ${hdrs} ${srcs})

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
