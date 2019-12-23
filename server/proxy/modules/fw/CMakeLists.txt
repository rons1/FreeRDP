find_package(HiRedis REQUIRED)
include_directories(${HIREDIS_INCLUDE_DIRS})

add_library(firewall SHARED
	firewall.c
)

target_link_libraries(firewall ${HIREDIS_LIBRARIES})
