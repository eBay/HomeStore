####################################################################################################################################
# add_flags(Flags <Languages> <Configurations>)
#
# The Flags argument contains the flag(s) to add
#
# The <Languages> argument contains the languages the flag(s) apply to; the default is "C CXX".
#
# The <Configurations> argument contains the configurations to add the flag(s) to; the default is just the global flags.  If
# specific configuration(s) are given then it is written to those only and not the global default
function(add_flags Flags)
    set(options)
    set(oneValueArgs Languages Configurations)
    set(multiValueArgs)
    cmake_parse_arguments(add_flags "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT Flags)
        message(ERROR "Add Flags: Flags cannot be empty.")
    endif()
    
    #set default languages and convert to list
    if(NOT add_flags_Languages)
        set(add_flags_Languages "C CXX")
    endif()
    separate_arguments(languages UNIX_COMMAND "${add_flags_Languages}")

    #set default configurations and convert to list
    if(NOT add_flags_Configurations)
    else()
        separate_arguments(configurations UNIX_COMMAND "${add_flags_Configurations}")
    endif()
        
    if(DEBUG_CMAKE)
        message(STATUS "Add Flags:")
        message(STATUS "Flags          - ${Flags}")
        message(STATUS "Languages      - ${add_flags_Languages}")
        if(DEFINED configurations) 
            message(STATUS "Configurations - ${add_flags_Configurations}")
        else()
            message(STATUS "Configurations - Global")        
        endif()
    endif()
    
    foreach(language ${languages})  
        string(TOUPPER "${language}" upper_language)
        if(DEFINED configurations)
            foreach(configuration ${configurations})
                string(TOUPPER "${configuration}" upper_configuration)
                if(NOT CMAKE_${upper_language}_FLAGS_${upper_configuration})
                    string(STRIP "${Flags}" CMAKE_MODIFIED_FLAGS)
                else()
                    set(CMAKE_MODIFIED_FLAGS "${CMAKE_${upper_language}_FLAGS_${upper_configuration}} ${Flags}")
                endif()
                string(STRIP "${CMAKE_MODIFIED_FLAGS}" CMAKE_MODIFIED_FLAGS)               
                string(REGEX REPLACE "[ ]+" " " CMAKE_MODIFIED_FLAGS "${CMAKE_MODIFIED_FLAGS}")
                set(CMAKE_${upper_language}_FLAGS_${upper_configuration} "${CMAKE_MODIFIED_FLAGS}" PARENT_SCOPE)
            endforeach()
        else()
            if(NOT CMAKE_${upper_language}_FLAGS)
                string(STRIP "${Flags}" CMAKE_MODIFIED_FLAGS)
            else()
                set(CMAKE_MODIFIED_FLAGS "${CMAKE_${upper_language}_FLAGS} ${Flags}")
            endif()
            string(STRIP "${CMAKE_MODIFIED_FLAGS}" CMAKE_MODIFIED_FLAGS)
            string(REGEX REPLACE "[ ]+" " " CMAKE_MODIFIED_FLAGS "${CMAKE_MODIFIED_FLAGS}")
            set(CMAKE_${upper_language}_FLAGS "${CMAKE_MODIFIED_FLAGS}" PARENT_SCOPE)
        endif()
    endforeach()    
endfunction(add_flags)

####################################################################################################################################
# remove_flag(Flag <Languages> <Configurations>)
#
# The Flag argument contains the regex of the flag to remove
#
# The <Languages> argument contains the languages the flag(s) apply to; the default is "C CXX".
#
# The <Configurations> argument contains the configurations to remove the flag(s) from; the default is the global flags and the 
# individual build configuration flags of "Debug, Release, ReleaseWithDebInfo, MinSizedRelease".  If specific configuration(s) are
# given then it is removed from the those only and the global.
function(remove_flag Flag)
    set(options)
    set(oneValueArgs Languages Configurations)
    set(multiValueArgs)
    cmake_parse_arguments(remove_flag "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    if(NOT Flag)
        message(ERROR "Remove Flag: Flag cannot be empty.")
    endif()
    
    #set default languages and convert to list
    if(NOT remove_flag_Languages)
        set(remove_flag_Languages "C CXX")
    endif()
    separate_arguments(languages UNIX_COMMAND "${remove_flag_Languages}")
    
    #set default configurations and convert to list
    if(NOT remove_flag_Configurations)
        set(remove_flag_Configurations "Debug Release RelWithDebInfo MinSizedRelease")        
    endif()
    separate_arguments(configurations UNIX_COMMAND "${remove_flag_Configurations}")
        
    if(DEBUG_CMAKE)
        message(STATUS "Remove Flag:")
        message(STATUS "Flag           - ${Flag}")
        message(STATUS "Languages      - ${remove_flag_Languages}")
        message(STATUS "Configurations - ${remove_flag_Configurations}")
    endif()
    
    foreach(language ${languages})  
        string(TOUPPER "${language}" upper_language)
        # remove from configurations
        foreach(configuration ${configurations})
            string(TOUPPER "${configuration}" upper_configuration)
            if(CMAKE_${upper_language}_FLAGS_${upper_configuration})
                string(REGEX REPLACE "${Flag}" "" CMAKE_MODIFIED_FLAGS "${CMAKE_${upper_language}_FLAGS_${upper_configuration}}")
                string(STRIP "${CMAKE_MODIFIED_FLAGS}" CMAKE_MODIFIED_FLAGS)
                string(REGEX REPLACE "[ ]+" " " CMAKE_MODIFIED_FLAGS "${CMAKE_MODIFIED_FLAGS}")
                set(CMAKE_${upper_language}_FLAGS_${upper_configuration} "${CMAKE_MODIFIED_FLAGS}" PARENT_SCOPE)
            endif()
        endforeach()
        
        #remove from global
        if(CMAKE_${upper_language}_FLAGS)
            string(REGEX REPLACE "${Flag}" "" CMAKE_MODIFIED_GLOBAL_FLAGS "${CMAKE_${upper_language}_FLAGS}") 
            string(STRIP "${CMAKE_MODIFIED_GLOBAL_FLAGS}" CMAKE_MODIFIED_GLOBAL_FLAGS)
            string(REGEX REPLACE "[ ]+" " " CMAKE_MODIFIED_FLAGS "${CMAKE_MODIFIED_FLAGS}")
            set(CMAKE_${upper_language}_FLAGS "${CMAKE_MODIFIED_GLOBAL_FLAGS}" PARENT_SCOPE)
        endif()
    endforeach()
endfunction(remove_flag)
