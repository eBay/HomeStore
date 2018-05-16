
set(ENDPOINT_SOURCE
        drive_endpoint.cpp
        net_endpoint.cpp
        )
add_library(hs_endpoint OBJECT ${ENDPOINT_SOURCE})
