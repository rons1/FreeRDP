
set(MODULE_NAME "mfa")
set(MODULE_PREFIX "FREERDP_PROXY_MFA")

# find CJOSE
find_path(CJOSE_INCLUDE_DIR cjose/cjose.h
		  /usr/include
		  /usr/local/include)

find_library(CJOSE_LIBRARY cjose)

find_package_handle_standard_args(CJOSE DEFAULT_MSG CJOSE_INCLUDE_DIR CJOSE_LIBRARY)

if(CJOSE_FOUND)
	set(CJOSE_LIBRARIES ${CJOSE_LIBRARY})
	set(CJOSE_INCLUDE_DIRS ${CJOSE_INCLUDE_DIR})
endif()

mark_as_advanced(CJOSE_INCLUDE_DIR CJOSE_LIBRARY)

# find jansson
find_path(JANSSON_INCLUDE_DIR jansson.h
          /usr/include
          /usr/local/include )

find_library(JANSSON_LIBRARY NAMES jansson
             PATHS /usr/lib /usr/local/lib )

set(JANSSON_LIBRARIES ${JANSSON_LIBRARY} )
set(JANSSON_INCLUDE_DIRS ${JANSSON_INCLUDE_DIR} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set JANSSON_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Jansson  DEFAULT_MSG
                                  JANSSON_LIBRARY JANSSON_INCLUDE_DIR)

mark_as_advanced(JANSSON_INCLUDE_DIR JANSSON_LIBRARY )

find_package(CURL REQUIRED)

include_directories(${CJOSE_INCLUDE_DIR})
include_directories(${JANSSON_INCLUDE_DIR})
include_directories(${CURL_INCLUDE_DIR})

list(APPEND ${MODULE_PREFIX}_LIBS ${CJOSE_LIBRARY})
list(APPEND ${MODULE_PREFIX}_LIBS ${JANSSON_LIBRARY})
list(APPEND ${MODULE_PREFIX}_LIBS ${CURL_LIBRARY})


add_library(mfa SHARED
mfa.c
token_validator.h
token_validator.c
)

target_link_libraries(${MODULE_NAME} ${${MODULE_PREFIX}_LIBS})
