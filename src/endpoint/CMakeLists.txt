
set(ENDPOINT_SOURCE
        drive_endpoint.cpp
        net_endpoint.cpp
        )
add_library(hs_endpoint STATIC ${ENDPOINT_SOURCE})
