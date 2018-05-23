#include "error.h"

namespace homestore {
std::error_condition const no_error;

const char* 
homstore_err_category::name() const noexcept {
   return "homestore";
}

std::string 
homstore_err_category::message(int ev) const {
   switch (ev) {
   case homestore_error::lba_not_exist:
        return "lba not exist in mapping table";
   }
   return "unknown error";
}

const std::error_category& 
homestore_category() {
   static homstore_err_category instance;
   return instance;
}

std::error_condition
make_error_condition(homestore_error e) {
   return std::error_condition(static_cast<int>(e), homestore_category());
}
}
