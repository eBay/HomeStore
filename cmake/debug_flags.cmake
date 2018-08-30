# This list is generated from the output of:
#
# gcc -Q --help=optimizers -O0
#
# with GCC 4.8.4 (Ubuntu 4.8.4-2ubuntu1-14.04.3). Yes, every one of these flags
# is on even with -O0 specified, and nothing changes when you add debugging 
# options (-g/-g3/-gdwarf-4/etc.) in there. This should be updated every time
# the version of GCC used to compile changes.
#
# If you add an option here, it is your responsibility to comment it, with the
# following convention (feel free to add your own if there's not one suitable).
# DO YOUR RESEARCH.
#
#     CBWITPOB: Can be wrong in the presence of bugs. When are you usually
#               debugging? When there's a bug. Optimizations that can be wrong
#               in the presence of bugs mean that, for example, you won't see
#               a variable be modified when it actually happens--if it's
#               modified due to the bug, as far as the debugger is concerned,
#               it wasn't modified by the program, and things like conditional
#               breakpoints won't work right, unless maybe it's a volatile
#               variable.
#     Inlining: Although GDB claims to track this correctly with -g3 and inject
#               the code while you're stepping, it does not. You'll either be
#               missing stack frames, or unable to view locals when you step
#               to that frame--even if those locals exist nowhere else (i.e.
#               not a function argument or tail return value).
#     Eliding: Behavior may not change, but who knows where the values come
#              from.
#     Hoisting: Your program is not running instructions in the order of the
#               code. Again, GDB claims to handle this, but it does not, or at
#               least not well.
#     Vectorizing: Great optimization, but the simulation of going through for
#                  loops is far from perfect, especially when you're dealing
#                  with bugs.
#
# And yes, these optimizations severely effect the quality of the debugging
# experience. Without these, you're lucky to be able to step into 80% of the
# stack, and of that 80%, you'll see anywhere from 50% to 100% of locals
# missing values. With these, I've never seen a stack frame I couldn't step
# into, and never seen <optimized out> when I look at a local.
#
set (REALLY_NO_OPTIMIZATION_FLAGS "-fno-short-enums"                                                    )# Binary-incompatible with code compiled otherwise.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-aggressive-loop-optimizations"  ) # Changes behavior on overflow.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-branch-count-reg"               )# Changes CPU instructions used.  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-dce                           )# Can be wrong in the presence of bugs (CBWITPOB).  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-delete-null-pointer-checks    )# CBWITPOB.  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-dse                           )# CBWITPOB.  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-early-inlining                )# NO INLINING! Because...  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-gcse-lm                       )# Changes CPU instructions used.  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-inline                        )# ...inlining also does things like elide locals.  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-ira-hoist-pressure            )# Might be irrelevant, but NO HOISTING!  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-ivopts                        )# Elides and changes instructions. CBWITPOB.  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-jump-tables                   )# Changes CPU instructions for switch statements.  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-move-loop-invariants          )# NO HOISTING!  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-peephole                      )# Exploiting CPU quirks. CBWITPOB.  set (REALLY_NO_OPTIMIZATION_FLAGS ="${REALLY_NO_OPTIMIZATION_FLAGS}+= -fno-prefetch-loop-arrays          )# Changes CPU instructions, even GCC manual is ambivalent.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-rename-registers"               )# Maybe wrong in the presence of bugs?
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-toplevel-reorder"               )# Elides unused static variable, reorders globals.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-coalesce-vars"             )# Elides temporaries. CBWITPOB.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-cselim"                    )# Reorders, violates C++ mem model, CBWITPOB.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-forwprop"                  )# Reorders and changes instructions. CBWITPOB.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-loop-if-convert"           )# Reorders and changes instructions. CBWITPOB.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-loop-im"                   )# Reorders and changes instructions. CBWITPOB.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-loop-optimize"             )# Reorders and changes instructions. CBWITPOB.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-phiprop"                   )# NO HOISTING! Reorders and changes. CBWITPOB.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-pta"                       )# Less analysis means maybe less interference.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-reassoc"                   )# Elides and vectories.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-scev-cprop"                )# Elides and changes instructions.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-vect-loop-version"         )# E&C.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-web"                            )# E&C.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fno-tree-slp-vectorize"             )# E&C.
set (REALLY_NO_OPTIMIZATION_FLAGS "${REALLY_NO_OPTIMIZATION_FLAGS} -fthreadsafe-statics"                )# Slightly smaller in code that doesn't need to be TS.

if (${CONAN_BUILD_COVERAGE})
  include (cmake/CodeCoverage.cmake)
  APPEND_COVERAGE_COMPILER_FLAGS()
  SETUP_TARGET_FOR_COVERAGE_GCOVR_XML(NAME coverage EXECUTABLE ctest DEPENDENCIES )
endif ()
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${REALLY_NO_OPTIMIZATION_FLAGS}")
