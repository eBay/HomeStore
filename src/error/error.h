#ifndef _ERROR_H_
#define _ERROR_H_

#include <system_error>

namespace homestore {

extern std::error_condition const no_error;
enum homestore_error {
    lba_not_exist = 1,
    partial_lba_not_exist = 2,
};

class homstore_err_category :
    public std::error_category {
public:
    virtual const char* name() const noexcept override;
    std::string message(int ev) const override;
    bool equivalent(const std::error_code &code, 
         int condition) const noexcept { return true; };
};

std::error_condition make_error_condition(homestore_error e);
}
template <>
struct std::is_error_condition_enum<homestore::homestore_error>
    : public true_type {};
#endif
