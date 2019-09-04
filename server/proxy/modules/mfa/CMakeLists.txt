
set(PLUGIN_NAME "mfa")
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

#
# FreeRDP: A Remote Desktop Protocol Implementation
# FreeRDP Proxy Server Demo C++ Module
#
# Copyright 2019 Kobi Mizrachi <kmizrachi18@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set(PLUGIN_NAME "proxy-mfa-plugin")

add_library(${PLUGIN_NAME} MODULE
    mfa.c
    mfa.h
    token_validator.h
    token_validator.c
)
target_link_libraries(${PLUGIN_NAME} ${${MODULE_PREFIX}_LIBS})
set_target_properties(${PLUGIN_NAME} PROPERTIES PREFIX "")
set_target_properties(${PLUGIN_NAME} PROPERTIES NO_SONAME 1)
set_target_properties(${PLUGIN_NAME} PROPERTIES
LIBRARY_OUTPUT_DIRECTORY "${FREERDP_PROXY_PLUGINDIR}")

