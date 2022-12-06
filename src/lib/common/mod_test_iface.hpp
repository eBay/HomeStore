class module_test {
public:
    virtual void try_run_one_iteration() = 0;
    virtual void try_run_last_iteration() = 0;
    virtual void run_start() = 0;
    virtual void try_init_iteration() = 0;
};

extern std::vector< module_test* > mod_tests;
